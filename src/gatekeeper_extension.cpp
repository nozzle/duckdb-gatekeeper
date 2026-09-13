#define DUCKDB_EXTENSION_MAIN
#include "gatekeeper_extension.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/type_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/view_catalog_entry.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/expression/bound_aggregate_expression.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/planner/expression/bound_window_expression.hpp"
#include "duckdb/planner/expression_iterator.hpp"
#include "duckdb/planner/logical_operator_visitor.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "engine_errors.hpp"
#include "function_policy.hpp"
#include "json_serializer.hpp"
#include "options.hpp"
#include <mutex>

namespace duckdb {
using namespace duckdb_yyjson;

static LogicalType ViolationType() {
	return LogicalType::STRUCT({{"rule", LogicalType::VARCHAR},
	                            {"message", LogicalType::VARCHAR},
	                            {"catalog", LogicalType::VARCHAR},
	                            {"schema", LogicalType::VARCHAR},
	                            {"table", LogicalType::VARCHAR},
	                            {"function_name", LogicalType::VARCHAR},
	                            {"position", LogicalType::BIGINT}});
}

static LogicalType ResultType() {
	return LogicalType::STRUCT({{"allowed", LogicalType::BOOLEAN},
	                            {"code", LogicalType::VARCHAR},
	                            {"violations", LogicalType::LIST(ViolationType())},
	                            {"error_type", LogicalType::VARCHAR},
	                            {"error_message", LogicalType::VARCHAR},
	                            {"position", LogicalType::BIGINT}});
}

static Value Position(int64_t position) { return position < 0 ? Value(LogicalType::BIGINT) : Value::BIGINT(position); }

static Value ResultValue(const gatekeeper::Result &result) {
	vector<Value> violations;
	for (auto &v : result.violations) {
		violations.push_back(
		    Value::STRUCT(ViolationType(), {Value(v.rule), Value(v.message), Value(v.catalog), Value(v.schema),
			                                Value(v.table), Value(v.function_name), Position(v.position)}));
	}
	return Value::STRUCT(ResultType(),
	                     {Value::BOOLEAN(result.allowed), Value(result.code), Value::LIST(ViolationType(), violations),
	                      Value(result.error_type), Value(result.error_message), Position(result.position)});
}

struct GatekeeperState : ScalarFunctionInfo {
	std::mutex mutex;
	bool configured = false;
	gatekeeper::Policy defaults;
};

struct OptionBinding : FunctionData {
	vector<string> names;
	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<OptionBinding>();
		result->names = names;
		return std::move(result);
	}
	bool Equals(const FunctionData &other) const override { return names == other.Cast<OptionBinding>().names; }
};

static unique_ptr<FunctionData> BindOptions(ClientContext &, ScalarFunction &function,
                                            vector<unique_ptr<Expression>> &arguments) {
	auto result = make_uniq<OptionBinding>();
	idx_t start = function.name == "gatekeeper_validate" ? 1 : 0;
	if (arguments.size() < start)
		throw BinderException("gatekeeper_validate requires SQL text");
	gatekeeper::Names seen;
	function.arguments.clear();
	if (start)
		function.arguments.push_back(LogicalType::VARCHAR);
	for (idx_t i = start; i < arguments.size(); i++) {
		auto name = arguments[i]->GetAlias();
		if (name.empty())
			throw BinderException("Gatekeeper options must be named typed arguments");
		if (!seen.insert(name).second)
			throw BinderException("duplicate Gatekeeper option: %s", name);
		LogicalType expected;
		try {
			expected = gatekeeper::OptionType(name);
		} catch (const std::invalid_argument &error) {
			throw BinderException(error.what());
		}
		auto actual = arguments[i]->return_type;
		if (actual.id() != LogicalTypeId::UNKNOWN && actual.id() != LogicalTypeId::SQLNULL) {
			if (expected == LogicalType::BOOLEAN && actual != expected)
				throw BinderException("%s requires BOOLEAN", name);
			if (expected == LogicalType::BIGINT && !actual.IsIntegral())
				throw BinderException("%s requires an integer", name);
			if (expected.id() == LogicalTypeId::LIST &&
			    (actual.id() != LogicalTypeId::LIST || (ListType::GetChildType(actual).id() != LogicalTypeId::VARCHAR &&
			                                            ListType::GetChildType(actual).id() != LogicalTypeId::SQLNULL)))
				throw BinderException("%s requires VARCHAR[]", name);
			if ((name == "allowed_tables" || name == "allowed_types") &&
			    (actual.id() != LogicalTypeId::LIST || (ListType::GetChildType(actual).id() != LogicalTypeId::STRUCT &&
			                                            ListType::GetChildType(actual).id() != LogicalTypeId::SQLNULL)))
				throw BinderException("%s requires STRUCT[]", name);
		}
		// Preserve table-entry field sets rather than silently coercing away unknown fields.
		function.arguments.push_back(name == "allowed_tables" || name == "allowed_types" ? actual : expected);
		result->names.push_back(name);
	}
	function.varargs = LogicalType::INVALID;
	return std::move(result);
}

static std::vector<std::pair<std::string, Value>> Options(DataChunk &args, const OptionBinding &binding, idx_t row,
                                                          idx_t start) {
	std::vector<std::pair<std::string, Value>> options;
	for (idx_t i = 0; i < binding.names.size(); i++)
		options.emplace_back(binding.names[i], args.data[i + start].GetValue(row));
	return options;
}

static void AuthorizeFunction(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding,
                              const string &name, gatekeeper::Result &result) {
	auto canonical = gatekeeper::CanonicalFunction(name);
	if (gatekeeper::FunctionDenied(policy, name) ||
	    (binding.synthesized_functions.count(canonical) && !gatekeeper::FunctionAllowed(policy, canonical))) {
		result.violations.emplace("function", "resolved function is not allowed: " + canonical, "", "", "", canonical);
		throw PermissionException("resolved function is not allowed");
	}
}

static void AuthorizeObject(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding,
                            CatalogEntry &entry, gatekeeper::Result &result) {
	switch (entry.type) {
	case CatalogType::SCALAR_FUNCTION_ENTRY:
	case CatalogType::AGGREGATE_FUNCTION_ENTRY:
	case CatalogType::TABLE_FUNCTION_ENTRY:
	case CatalogType::MACRO_ENTRY:
	case CatalogType::TABLE_MACRO_ENTRY:
	case CatalogType::PRAGMA_FUNCTION_ENTRY:
		AuthorizeFunction(policy, binding, entry.name, result);
		return;
	case CatalogType::TYPE_ENTRY: {
		auto &type = entry.Cast<TypeCatalogEntry>();
		if (!binding.caller_types.count(gatekeeper::Lower(type.name)))
			return; // Types inside trusted expansions are not caller-requested capabilities.
		if (type.internal && gatekeeper::BuiltinTypes().count(gatekeeper::Lower(type.name)))
			return; // DefaultTypeGenerator installs built-ins in each catalog's main schema.
		auto catalog = type.schema.catalog.GetName(), schema = type.schema.name;
		if (!gatekeeper::TypeAllowed(policy, catalog, schema, type.name, true)) {
			result.violations.emplace("type", "resolved type is not allowed: " + type.name, catalog, schema);
			throw PermissionException("resolved type is not allowed");
		}
		return;
	}
	default:
		break;
	}
	if (entry.type != CatalogType::TABLE_ENTRY && entry.type != CatalogType::VIEW_ENTRY)
		return;
	auto &object = entry.Cast<StandardEntry>();
	auto catalog = object.schema.catalog.GetName(), schema = object.schema.name, name = object.name;
	auto folded_catalog = gatekeeper::Lower(catalog), folded_schema = gatekeeper::Lower(schema),
	     folded_name = gatekeeper::Lower(name);
	bool explicit_table = policy.allowed_tables.count({folded_catalog, folded_schema, folded_name}) ||
	                      policy.allowed_tables.count({"", folded_schema, folded_name});
	if (entry.internal && !explicit_table)
		result.violations.emplace("internal_object", "internal object requires explicit allowed_tables permission",
		                          catalog, schema, name);
	if (policy.catalogs && !policy.allowed_catalogs.count(folded_catalog))
		result.violations.emplace("catalog", "catalog is not allowed", catalog, schema, name);
	if (policy.schemas && !policy.allowed_schemas.count(folded_schema))
		result.violations.emplace("schema", "schema is not allowed", catalog, schema, name);
	if (policy.tables && !explicit_table)
		result.violations.emplace("table", "object is not allowed", catalog, schema, name);
	if (!result.violations.empty())
		throw PermissionException("resolved object is not allowed");
}

// Direct FunctionBinder/collation lookups can bypass CatalogEntryRetriever. This
// backstop checks surviving bound expressions; it cannot undo earlier bind-time work.
static void AuthorizePlan(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding,
                          LogicalOperator &root, gatekeeper::Result &result) {
	vector<LogicalOperator *> operators{&root};
	while (!operators.empty()) {
		auto op = operators.back();
		operators.pop_back();
		for (auto &child : op->children)
			operators.push_back(child.get());
		// A catalog table's physical scan is authorized by its object identity.
		if (op->type == LogicalOperatorType::LOGICAL_GET && op->Cast<LogicalGet>().function.name != "seq_scan")
			AuthorizeFunction(policy, binding, op->Cast<LogicalGet>().function.name, result);
		LogicalOperatorVisitor::EnumerateExpressions(*op, [&](unique_ptr<Expression> *expr) {
			ExpressionIterator::EnumerateExpression(*expr, [&](Expression &child) {
				if (child.GetExpressionClass() == ExpressionClass::BOUND_FUNCTION)
					AuthorizeFunction(policy, binding, child.Cast<BoundFunctionExpression>().function.name, result);
				if (child.GetExpressionClass() == ExpressionClass::BOUND_AGGREGATE)
					AuthorizeFunction(policy, binding, child.Cast<BoundAggregateExpression>().function.name, result);
				if (child.GetExpressionClass() == ExpressionClass::BOUND_WINDOW) {
					auto &window = child.Cast<BoundWindowExpression>();
					if (window.aggregate)
						AuthorizeFunction(policy, binding, window.aggregate->name, result);
				}
			});
		});
	}
}

static gatekeeper::Result Check(ClientContext &context, const gatekeeper::Policy &policy, const string &sql) {
	gatekeeper::Result result;
	bool binding = false;
	try {
		if (sql.find('\0') != string::npos)
			throw InvalidInputException("SQL contains a NUL byte");
		if (sql.size() > policy.bytes)
			return {false, "forbidden", "", "", {{"limit", "SQL exceeds max_ast_bytes input bound"}}};
		Parser parser(context.GetParserOptions());
		parser.ParseQuery(sql);
		if (parser.statements.empty())
			throw InvalidInputException("SQL contains no statements");
		if (parser.statements.size() > policy.statements)
			return {false, "forbidden", "", "", {{"limit", "statement count exceeds policy"}}};
		unique_ptr<yyjson_mut_doc, decltype(&yyjson_mut_doc_free)> doc(yyjson_mut_doc_new(nullptr),
		                                                               yyjson_mut_doc_free);
		if (!doc)
			throw std::bad_alloc();
		auto root = yyjson_mut_obj(doc.get());
		yyjson_mut_doc_set_root(doc.get(), root);
		yyjson_mut_obj_add_false(doc.get(), root, "error");
		auto statements = yyjson_mut_arr(doc.get());
		yyjson_mut_obj_add_val(doc.get(), root, "statements", statements);
		SerializationOptions serialization_options;
		serialization_options.serialization_compatibility = SerializationCompatibility::Latest();
		for (auto &statement : parser.statements) {
			if (statement->type != StatementType::SELECT_STATEMENT)
				return {false, "unsupported", "", "", {{"statement", "only supported read statements are permitted"}}};
			yyjson_mut_arr_append(statements, JsonSerializer::Serialize(statement->Cast<SelectStatement>(), doc.get(),
			                                                            true, true, true, serialization_options));
		}
		unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> ast(yyjson_mut_doc_imut_copy(doc.get(), nullptr),
		                                                       yyjson_doc_free);
		if (!ast)
			throw std::bad_alloc();
		size_t bytes = 0;
		unique_ptr<char, decltype(&free)> serialized(yyjson_write(ast.get(), 0, &bytes), free);
		if (!serialized)
			throw std::bad_alloc();
		if (bytes > policy.bytes)
			return {false, "forbidden", "", "", {{"limit", "serialized AST exceeds max_ast_bytes"}}};
		gatekeeper::BindingPolicy binding_policy;
		result = gatekeeper::Validate(yyjson_doc_get_root(ast.get()), policy, &binding_policy);
		if (!result.allowed)
			return result;
		binding = true;
		for (auto &statement : parser.statements) {
			auto binder = Binder::CreateBinder(context);
			binder->SetBindingMode(BindingMode::EXTRACT_REPLACEMENT_SCANS);
			binder->SetCatalogLookupCallback(
			    [&](CatalogEntry &entry) { AuthorizeObject(policy, binding_policy, entry, result); });
			auto bound = binder->Bind(*statement);
			if (bound.plan)
				AuthorizePlan(policy, binding_policy, *bound.plan, result);
			if (!binder->GetReplacementScans().empty()) {
				result.allowed = false;
				result.code = "unsupported";
				result.violations.emplace("replacement_scan",
				                          "host-language or implicit replacement scans cannot be authorized; use an "
				                          "explicit admitted reader or trusted catalog object");
				return result;
			}
		}
		return result;
	} catch (const ParserException &error) {
		ErrorData data(error);
		result.code = "parser";
		result.error_type = "parser";
		result.error_message = data.RawMessage();
		auto position = data.ExtraInfo().find("position");
		if (position != data.ExtraInfo().end()) {
			try {
				result.position = std::stoll(position->second);
			} catch (...) {
			}
		}
	} catch (const std::invalid_argument &error) {
		result.code = binding ? "binding" : "invalid_input";
		result.error_message = error.what();
	} catch (const InvalidInputException &error) {
		result.code = binding ? "binding" : "invalid_input";
		if (binding)
			result.error_type = "Invalid Input";
		result.error_message = ErrorData(error).RawMessage();
	} catch (const Exception &error) {
		ErrorData data(error);
		if (gatekeeper::PropagateEngineError(data.Type()))
			throw;
		result.code = gatekeeper::EngineErrorCode(binding);
		result.error_type = Exception::ExceptionTypeToString(data.Type());
		result.error_message = data.RawMessage();
	} catch (const std::bad_alloc &) {
		throw;
	} catch (const std::exception &error) {
		ErrorData data(error);
		if (gatekeeper::PropagateEngineError(data.Type()))
			throw;
		result.code = gatekeeper::EngineErrorCode(binding);
		result.error_type = Exception::ExceptionTypeToString(data.Type());
		result.error_message = data.RawMessage();
	}
	result.allowed = false;
	if (!result.violations.empty()) {
		result.code = "forbidden";
		result.error_type.clear();
		result.error_message.clear();
	}
	return result;
}

static void GatekeeperValidate(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &expression = state.expr.Cast<BoundFunctionExpression>();
	auto &configuration = expression.function.function_info->Cast<GatekeeperState>();
	gatekeeper::Policy defaults;
	{
		std::lock_guard<std::mutex> lock(configuration.mutex);
		defaults = configuration.defaults;
	}
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto sql = args.data[0].GetValue(row);
		gatekeeper::Result decision;
		try {
			auto policy = defaults;
			gatekeeper::ApplyOptions(policy, Options(args, expression.bind_info->Cast<OptionBinding>(), row, 1));
			if (sql.IsNull())
				decision = {false, "invalid_input", "", "NULL SQL input", {}};
			else
				decision = Check(state.GetContext(), policy, sql.GetValue<string>());
		} catch (const std::invalid_argument &error) {
			decision = {false, "invalid_input", "", error.what(), {}};
		}
		result.SetValue(row, ResultValue(decision));
	}
}

static void Configure(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &expression = state.expr.Cast<BoundFunctionExpression>();
	auto &config = expression.function.function_info->Cast<GatekeeperState>();
	if (args.size() != 1)
		throw InvalidInputException("gatekeeper_configure requires one row");
	try {
		gatekeeper::Policy policy;
		gatekeeper::ApplyOptions(policy, Options(args, expression.bind_info->Cast<OptionBinding>(), 0, 0));
		std::lock_guard<std::mutex> lock(config.mutex);
		if (config.configured)
			throw InvalidInputException("Gatekeeper defaults are already configured");
		config.defaults = std::move(policy);
		config.configured = true;
	} catch (const std::invalid_argument &error) {
		throw InvalidInputException(error.what());
	}
	result.SetValue(0, Value::BOOLEAN(true));
}

static void LoadInternal(ExtensionLoader &loader) {
	auto config = make_shared_ptr<GatekeeperState>();
	ScalarFunction validate("gatekeeper_validate", {LogicalType::VARCHAR}, ResultType(), GatekeeperValidate,
	                        BindOptions);
	ScalarFunction configure("gatekeeper_configure", {}, LogicalType::BOOLEAN, Configure, BindOptions);
	for (auto function : {validate, configure}) {
		function.varargs = LogicalType::ANY;
		function.null_handling = FunctionNullHandling::SPECIAL_HANDLING;
		function.stability = FunctionStability::VOLATILE;
		function.function_info = config;
		loader.RegisterFunction(function);
	}
}
void GatekeeperExtension::Load(ExtensionLoader &loader) { LoadInternal(loader); }
std::string GatekeeperExtension::Name() { return "gatekeeper"; }
std::string GatekeeperExtension::Version() const { return "0.1.0"; }
} // namespace duckdb
extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(gatekeeper, loader) { duckdb::LoadInternal(loader); }
}
