#define DUCKDB_EXTENSION_MAIN
#include "gatekeeper_extension.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/view_catalog_entry.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
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
			if (name == "allowed_tables" &&
			    (actual.id() != LogicalTypeId::LIST || (ListType::GetChildType(actual).id() != LogicalTypeId::STRUCT &&
			                                            ListType::GetChildType(actual).id() != LogicalTypeId::SQLNULL)))
				throw BinderException("allowed_tables requires STRUCT[]");
		}
		// Preserve table-entry field sets rather than silently coercing away unknown fields.
		function.arguments.push_back(name == "allowed_tables" ? actual : expected);
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

static void AuthorizeObject(const gatekeeper::Policy &policy, CatalogEntry &entry, gatekeeper::Result &result) {
	if (entry.type != CatalogType::TABLE_ENTRY && entry.type != CatalogType::VIEW_ENTRY)
		return;
	auto &object = entry.Cast<StandardEntry>();
	auto catalog = object.schema.catalog.GetName(), schema = object.schema.name, name = object.name;
	if (policy.catalogs && !policy.allowed_catalogs.count(catalog))
		result.violations.emplace("catalog", "catalog is not allowed", catalog, schema, name);
	if (policy.schemas && !policy.allowed_schemas.count(schema))
		result.violations.emplace("schema", "schema is not allowed", catalog, schema, name);
	if (policy.tables && !policy.allowed_tables.count({catalog, schema, name}) &&
	    !policy.allowed_tables.count({"", schema, name}))
		result.violations.emplace("table", "object is not allowed", catalog, schema, name);
	if (!result.violations.empty())
		throw PermissionException("resolved object is not allowed");
}

static gatekeeper::Result Check(ClientContext &context, const gatekeeper::Policy &policy, const string &sql) {
	gatekeeper::Result result;
	bool binding = false;
	try {
		if (sql.find('\0') != string::npos)
			throw InvalidInputException("SQL contains a NUL byte");
		if (sql.size() > policy.bytes)
			return {false, "forbidden", "", "", {{"limit", "SQL exceeds max_ast_bytes input bound"}}};
		Parser parser;
		parser.ParseQuery(sql);
		if (parser.statements.empty() || parser.statements.size() > policy.statements)
			return {false, "forbidden", "", "", {{"limit", "statement count exceeds policy or SQL is empty"}}};
		unique_ptr<yyjson_mut_doc, decltype(&yyjson_mut_doc_free)> doc(yyjson_mut_doc_new(nullptr),
		                                                               yyjson_mut_doc_free);
		if (!doc)
			throw std::bad_alloc();
		auto root = yyjson_mut_obj(doc.get());
		yyjson_mut_doc_set_root(doc.get(), root);
		yyjson_mut_obj_add_false(doc.get(), root, "error");
		auto statements = yyjson_mut_arr(doc.get());
		yyjson_mut_obj_add_val(doc.get(), root, "statements", statements);
		for (auto &statement : parser.statements) {
			if (statement->type != StatementType::SELECT_STATEMENT)
				return {false, "unsupported", "", "", {{"statement", "only supported read statements are permitted"}}};
			yyjson_mut_arr_append(
			    statements, JsonSerializer::Serialize(statement->Cast<SelectStatement>(), doc.get(), true, true, true));
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
		result = gatekeeper::Validate(yyjson_doc_get_root(ast.get()), policy);
		if (!result.allowed)
			return result;
		binding = true;
		for (auto &statement : parser.statements) {
			auto binder = Binder::CreateBinder(context);
			binder->SetBindingMode(BindingMode::EXTRACT_REPLACEMENT_SCANS);
			binder->SetCatalogLookupCallback([&](CatalogEntry &entry) { AuthorizeObject(policy, entry, result); });
			auto bound = binder->Bind(*statement);
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
		result.code = "binding";
		result.error_type = Exception::ExceptionTypeToString(data.Type());
		result.error_message = data.RawMessage();
	} catch (const std::exception &error) {
		ErrorData data(error);
		result.code = "binding";
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
