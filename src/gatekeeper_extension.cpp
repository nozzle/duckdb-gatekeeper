#define DUCKDB_EXTENSION_MAIN
#include "gatekeeper_extension.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/type_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/view_catalog_entry.hpp"
#include "duckdb/function/replacement_scan.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/bound_parameter_map.hpp"
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
#include <map>

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

static LogicalType IdentityType(bool object) {
	return LogicalType::STRUCT({{"catalog", LogicalType::VARCHAR},
	                            {"schema", LogicalType::VARCHAR},
	                            {object ? "table" : "name", LogicalType::VARCHAR},
	                            {"type", LogicalType::VARCHAR}});
}

static LogicalType ResultType() {
	return LogicalType::STRUCT({{"allowed", LogicalType::BOOLEAN},
	                            {"code", LogicalType::VARCHAR},
	                            {"violations", LogicalType::LIST(ViolationType())},
	                            {"error_type", LogicalType::VARCHAR},
	                            {"error_message", LogicalType::VARCHAR},
	                            {"position", LogicalType::BIGINT},
	                            {"objects", LogicalType::LIST(IdentityType(true))},
	                            {"functions", LogicalType::LIST(IdentityType(false))}});
}

static Value Position(int64_t position) { return position < 0 ? Value(LogicalType::BIGINT) : Value::BIGINT(position); }

static Value ResultValue(const gatekeeper::Result &result) {
	vector<Value> violations;
	for (auto &v : result.violations) {
		violations.push_back(
		    Value::STRUCT(ViolationType(), {Value(v.rule), Value(v.message), Value(v.catalog), Value(v.schema),
			                                Value(v.table), Value(v.function_name), Position(v.position)}));
	}
	auto identities = [&](const std::set<gatekeeper::Identity> &entries, bool object) {
		vector<Value> values;
		if (result.allowed) {
			for (const auto &entry : entries)
				values.push_back(Value::STRUCT(IdentityType(object), {Value(entry.catalog), Value(entry.schema),
				                                                      Value(entry.name), Value(entry.type)}));
		}
		return Value::LIST(IdentityType(object), values);
	};
	return Value::STRUCT(ResultType(),
	                     {Value::BOOLEAN(result.allowed), Value(result.code), Value::LIST(ViolationType(), violations),
	                      Value(result.error_type), Value(result.error_message), Position(result.position),
	                      identities(result.objects, true), identities(result.functions, false)});
}

static constexpr const char *POLICY_SETTING = "gatekeeper_policy";

static void SetPolicy(ClientContext &, SetScope scope, Value &value) {
	if (scope == SetScope::SESSION)
		throw InvalidInputException("gatekeeper_policy is global-only");
	try {
		value = gatekeeper::PolicyValue(gatekeeper::ReadPolicy(value));
	} catch (const std::invalid_argument &error) {
		throw InvalidInputException(error.what());
	}
}

static gatekeeper::Policy GlobalPolicy(ClientContext &context) {
	auto &config = DBConfig::GetConfig(context);
	Value value;
	if (!config.TryGetCurrentSetting(POLICY_SETTING, value))
		throw std::invalid_argument("gatekeeper_policy is unavailable");
	return gatekeeper::ReadPolicy(value);
}

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
	case CatalogType::PRAGMA_FUNCTION_ENTRY: {
		AuthorizeFunction(policy, binding, entry.name, result);
		auto &function = entry.Cast<StandardEntry>();
		if ((entry.type == CatalogType::TABLE_FUNCTION_ENTRY || entry.type == CatalogType::TABLE_MACRO_ENTRY) &&
		    binding.runtime_table_functions.count(gatekeeper::Lower(entry.name)) &&
		    (entry.type != CatalogType::TABLE_FUNCTION_ENTRY || function.schema.catalog.GetName() != "system" ||
		     function.schema.name != "main")) {
			result.violations.emplace("bind_time_expression",
			                          "runtime arguments require a system table-in-out function",
			                          function.schema.catalog.GetName(), function.schema.name, "", entry.name);
			throw PermissionException("untrusted table-in-out function");
		}
		if (binding.literal_constructors.count(gatekeeper::Lower(entry.name)) &&
		    (entry.type != CatalogType::SCALAR_FUNCTION_ENTRY || function.schema.catalog.GetName() != "system" ||
		     function.schema.name != "main")) {
			result.violations.emplace("bind_time_expression", "literal constructor must resolve to a system builtin",
			                          function.schema.catalog.GetName(), function.schema.name, "", entry.name);
			throw PermissionException("untrusted bind-time constructor");
		}
		string type = entry.type == CatalogType::SCALAR_FUNCTION_ENTRY      ? "scalar"
		              : entry.type == CatalogType::AGGREGATE_FUNCTION_ENTRY ? "aggregate"
		              : entry.type == CatalogType::TABLE_FUNCTION_ENTRY     ? "table"
		              : entry.type == CatalogType::MACRO_ENTRY              ? "macro"
		              : entry.type == CatalogType::TABLE_MACRO_ENTRY        ? "table_macro"
		                                                                    : "pragma";
		result.functions.insert({function.schema.catalog.GetName(), function.schema.name, entry.name, type});
		return;
	}
	case CatalogType::TYPE_ENTRY: {
		auto &type = entry.Cast<TypeCatalogEntry>();
		if (!binding.caller_types.count(gatekeeper::Lower(type.name)))
			return; // Types inside trusted expansions are not caller-requested capabilities.
		if (type.internal && gatekeeper::BuiltinTypes().count(gatekeeper::Lower(type.name)))
			return; // DefaultTypeGenerator installs built-ins in each catalog's main schema.
		auto catalog = type.schema.catalog.GetName(), schema = type.schema.name;
		if (policy.catalogs && !policy.allowed_catalogs.count(gatekeeper::Lower(catalog)))
			result.violations.emplace("catalog", "type catalog is not allowed", catalog, schema);
		if (policy.schemas && !policy.allowed_schemas.count(gatekeeper::Lower(schema)))
			result.violations.emplace("schema", "type schema is not allowed", catalog, schema);
		if (!gatekeeper::TypeAllowed(policy, catalog, schema, type.name, true)) {
			result.violations.emplace("type", "resolved type is not allowed: " + type.name, catalog, schema);
			throw PermissionException("resolved type is not allowed");
		}
		if (!result.violations.empty())
			throw PermissionException("resolved type namespace is not allowed");
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
	result.objects.insert({catalog, schema, name, entry.type == CatalogType::TABLE_ENTRY ? "table" : "view"});
}

// Replacement scans run when a table name resolves to no catalog object. DuckDB's callbacks only
// construct a TableRef; the reader binds (and may open files) afterwards. Gatekeeper installs the
// first callback at LOAD and, while a validation is binding on this thread, decides before that
// bind happens: with replacement scans disabled in either layer, any claimed name is denied; with
// them enabled, the resolved reader is authorized like a caller-written table function.
struct ValidationScope {
	const gatekeeper::Policy &policy;
	const gatekeeper::Policy &ceiling;
	gatekeeper::Result &result;
	gatekeeper::Names authorized; // table names admitted through replacement, case-folded
};
static thread_local ValidationScope *active_scope = nullptr;
struct ScopeGuard {
	explicit ScopeGuard(ValidationScope &scope) { active_scope = &scope; }
	~ScopeGuard() { active_scope = nullptr; }
};

static unique_ptr<TableRef> GatekeeperReplacementScan(ClientContext &context, ReplacementScanInput &input,
                                                      optional_ptr<ReplacementScanData>) {
	auto scope = active_scope;
	if (!scope)
		return nullptr; // Ordinary connections are unaffected.
	auto path = ReplacementScan::GetFullPath(input);
	auto deny = [&](const string &rule, const string &message, const string &function = "") {
		scope->result.violations.emplace(rule, message, input.catalog_name, input.schema_name, input.table_name,
		                                 function);
		throw PermissionException("replacement scan is not allowed");
	};
	auto &config = DBConfig::GetConfig(context);
	for (auto &scan : config.replacement_scans) {
		if (scan.function == GatekeeperReplacementScan)
			continue;
		// Other callbacks construct a TableRef without binding it; nothing is opened here.
		auto replacement = scan.function(context, input, scan.data.get());
		if (!replacement)
			continue;
		if (!scope->policy.replacement_scans || !scope->ceiling.replacement_scans)
			deny("replacement_scan", "replacement scans are disabled: " + path);
		if (replacement->type != TableReferenceType::TABLE_FUNCTION)
			deny("replacement_scan", "host-language replacement scan cannot be authorized: " + path);
		auto &function = replacement->Cast<TableFunctionRef>().function;
		if (!function || function->GetExpressionClass() != ExpressionClass::FUNCTION)
			deny("replacement_scan", "replacement scan has no resolvable function: " + path);
		auto name = function->Cast<FunctionExpression>().function_name;
		for (const auto *layer : {&scope->ceiling, &scope->policy}) {
			if (!layer->table_functions)
				deny("table_function", "table functions are disabled", name);
			if (!gatekeeper::FunctionAllowed(*layer, name))
				deny("function", "replacement scan function is not allowed: " + gatekeeper::CanonicalFunction(name),
				     gatekeeper::CanonicalFunction(name));
		}
		scope->authorized.insert(gatekeeper::Lower(input.table_name));
		scope->result.objects.insert({"", "", path, "replacement"});
		return replacement;
	}
	return nullptr; // No scan claims the name; DuckDB reports the missing table.
}

// Direct FunctionBinder/collation lookups can bypass CatalogEntryRetriever. This
// backstop checks surviving bound expressions; it cannot undo earlier bind-time work.
static void AuthorizePlan(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding,
                          LogicalOperator &root, gatekeeper::Result &result) {
	auto function = [&](const string &name, const string &type) {
		AuthorizeFunction(policy, binding, name, result);
		for (const auto &entry : result.functions)
			if (entry.name == name && entry.type == type)
				return;
		// A bound implementation does not expose catalog provenance. Do not infer it
		// from a same-named catalog entry of a different kind or do another lookup.
		result.functions.insert({"", "", name, type});
	};
	vector<LogicalOperator *> operators{&root};
	while (!operators.empty()) {
		auto op = operators.back();
		operators.pop_back();
		for (auto &child : op->children)
			operators.push_back(child.get());
		// A catalog table's physical scan is authorized by its object identity.
		if (op->type == LogicalOperatorType::LOGICAL_GET && op->Cast<LogicalGet>().function.name != "seq_scan")
			function(op->Cast<LogicalGet>().function.name, "table");
		LogicalOperatorVisitor::EnumerateExpressions(*op, [&](unique_ptr<Expression> *expr) {
			ExpressionIterator::EnumerateExpression(*expr, [&](Expression &child) {
				if (child.GetExpressionClass() == ExpressionClass::BOUND_FUNCTION)
					function(child.Cast<BoundFunctionExpression>().function.name, "scalar");
				if (child.GetExpressionClass() == ExpressionClass::BOUND_AGGREGATE)
					function(child.Cast<BoundAggregateExpression>().function.name, "aggregate");
				if (child.GetExpressionClass() == ExpressionClass::BOUND_WINDOW) {
					auto &window = child.Cast<BoundWindowExpression>();
					if (window.aggregate)
						function(window.aggregate->name, "aggregate");
					else {
						static const std::map<ExpressionType, string> windows = {
						    {ExpressionType::WINDOW_ROW_NUMBER, "row_number"},
						    {ExpressionType::WINDOW_RANK, "rank"},
						    {ExpressionType::WINDOW_RANK_DENSE, "dense_rank"},
						    {ExpressionType::WINDOW_NTILE, "ntile"},
						    {ExpressionType::WINDOW_PERCENT_RANK, "percent_rank"},
						    {ExpressionType::WINDOW_CUME_DIST, "cume_dist"},
						    {ExpressionType::WINDOW_FIRST_VALUE, "first_value"},
						    {ExpressionType::WINDOW_LAST_VALUE, "last_value"},
						    {ExpressionType::WINDOW_LEAD, "lead"},
						    {ExpressionType::WINDOW_LAG, "lag"},
						    {ExpressionType::WINDOW_NTH_VALUE, "nth_value"},
						    {ExpressionType::WINDOW_FILL, "fill"}};
						auto found = windows.find(window.GetExpressionType());
						if (found != windows.end())
							function(found->second, "window");
					}
				}
			});
		});
	}
}

static gatekeeper::Result Check(ClientContext &context, const gatekeeper::Policy &policy,
                                const gatekeeper::Policy &ceiling, const string &sql) {
	gatekeeper::Result result;
	bool binding = false;
	try {
		if (sql.find('\0') != string::npos)
			throw InvalidInputException("SQL contains a NUL byte");
		if (sql.size() > std::min(policy.bytes, ceiling.bytes))
			return {false, "forbidden", "", "", {{"limit", "SQL exceeds max_ast_bytes input bound"}}};
		Parser parser(context.GetParserOptions());
		parser.ParseQuery(sql);
		if (parser.statements.empty())
			throw InvalidInputException("SQL contains no statements");
		if (parser.statements.size() > std::min(policy.statements, ceiling.statements))
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
		if (bytes > std::min(policy.bytes, ceiling.bytes))
			return {false, "forbidden", "", "", {{"limit", "serialized AST exceeds max_ast_bytes"}}};
		gatekeeper::BindingPolicy binding_policy;
		result = gatekeeper::Validate(yyjson_doc_get_root(ast.get()), policy, &binding_policy, &ceiling);
		if (!result.allowed)
			return result;
		binding = true;
		for (auto &statement : parser.statements) {
			case_insensitive_map_t<BoundParameterData> parameter_data;
			BoundParameterMap parameters(parameter_data);
			auto binder = Binder::CreateBinder(context);
			binder->SetParameters(parameters);
			binder->SetBindingMode(BindingMode::EXTRACT_REPLACEMENT_SCANS);
			binder->SetCatalogLookupCallback([&](CatalogEntry &entry) {
				AuthorizeObject(ceiling, binding_policy, entry, result);
				AuthorizeObject(policy, binding_policy, entry, result);
			});
			ValidationScope scope{policy, ceiling, result, {}};
			BoundStatement bound;
			{
				ScopeGuard guard(scope);
				bound = binder->Bind(*statement);
			}
			// Unlike Planner::CreatePlan, never turn ParameterNotResolved into a partial success.
			// parameters.rebind is a cache hint, not incomplete binding.
			if (!bound.plan)
				throw BinderException(
				    "Validation requires a complete bound plan; parameter values or types may be needed");
			if (bound.plan) {
				AuthorizePlan(ceiling, binding_policy, *bound.plan, result);
				AuthorizePlan(policy, binding_policy, *bound.plan, result);
			}
			// Backstop: every replacement DuckDB recorded must have passed the Gatekeeper callback.
			for (auto &entry : binder->GetReplacementScans())
				if (!scope.authorized.count(gatekeeper::Lower(entry.first)))
					result.violations.emplace("replacement_scan", "replacement scan was not authorized: " + entry.first,
					                          "", "", entry.first);
			if (!result.violations.empty())
				throw PermissionException("unauthorized replacement scan");
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
		if (data.Type() == ExceptionType::PARAMETER_NOT_RESOLVED)
			result.error_message = "Validation cannot complete binding without parameter values or types";
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
	gatekeeper::Policy defaults;
	std::string configuration_error;
	try {
		defaults = GlobalPolicy(state.GetContext());
	} catch (const std::invalid_argument &error) {
		configuration_error = error.what();
	}
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto sql = args.data[0].GetValue(row);
		gatekeeper::Result decision;
		try {
			if (!configuration_error.empty())
				throw std::invalid_argument(configuration_error);
			auto policy = defaults;
			gatekeeper::ApplyOptions(policy, Options(args, expression.bind_info->Cast<OptionBinding>(), row, 1));
			if (sql.IsNull())
				decision = {false, "invalid_input", "", "NULL SQL input", {}};
			else
				decision = Check(state.GetContext(), policy, defaults, sql.GetValue<string>());
		} catch (const std::invalid_argument &error) {
			decision = {false, "invalid_input", "", error.what(), {}};
		}
		result.SetValue(row, ResultValue(decision));
	}
}

struct ConfigureBinding : FunctionData {
	Value policy;
	explicit ConfigureBinding(Value policy) : policy(std::move(policy)) {}
	unique_ptr<FunctionData> Copy() const override { return make_uniq<ConfigureBinding>(policy); }
	bool Equals(const FunctionData &other) const override { return policy == other.Cast<ConfigureBinding>().policy; }
};

struct ConfigureState : GlobalTableFunctionState {
	bool finished = false;
};

static unique_ptr<GlobalTableFunctionState> InitConfigure(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<ConfigureState>();
}

static unique_ptr<FunctionData> BindConfigure(ClientContext &, TableFunctionBindInput &input,
                                              vector<LogicalType> &types, vector<string> &names) {
	try {
		// DuckDB overwrites duplicate named parameters in its map before calling bind.
		if (input.ref.function &&
		    input.ref.function->Cast<FunctionExpression>().children.size() != input.named_parameters.size())
			throw std::invalid_argument("duplicate Gatekeeper configuration option");
		gatekeeper::Policy policy;
		std::vector<std::pair<std::string, Value>> options;
		for (const auto &option : input.named_parameters) {
			auto value = option.second;
			// ANY preserves original types and nested field names; only integer widening is permitted.
			if (!value.IsNull() && gatekeeper::OptionType(option.first) == LogicalType::BIGINT &&
			    value.type().IsIntegral())
				value = Value::BIGINT(value.GetValue<int64_t>());
			options.emplace_back(option.first, std::move(value));
		}
		gatekeeper::ApplyOptions(policy, options);
		types.push_back(LogicalType::BOOLEAN);
		names.push_back("Success");
		return make_uniq<ConfigureBinding>(gatekeeper::PolicyValue(policy));
	} catch (const std::invalid_argument &error) {
		throw InvalidInputException(error.what());
	}
}

static void Configure(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<ConfigureState>();
	if (state.finished)
		return;
	auto &config = DBConfig::GetConfig(context);
	config.CheckLock(POLICY_SETTING);
	auto value = input.bind_data->Cast<ConfigureBinding>().policy;
	SetPolicy(context, SetScope::GLOBAL, value);
	config.SetOption(POLICY_SETTING, std::move(value));
	state.finished = true;
	output.SetCardinality(1);
	output.SetValue(0, 0, Value::BOOLEAN(true));
}

// The grammar and inventory are generated from exactly this engine release. DuckDB's own footer check
// compares the same string but can be disabled with allow_extensions_metadata_mismatch, so refuse to
// load into any other engine build here as well.
static constexpr const char *SUPPORTED_DUCKDB_VERSION = "v1.5.5";

static void LoadInternal(ExtensionLoader &loader) {
	if (string(DuckDB::LibraryVersion()) != SUPPORTED_DUCKDB_VERSION) {
		throw InvalidInputException("Gatekeeper 0.1.0 supports DuckDB %s only; this engine is %s",
		                            SUPPORTED_DUCKDB_VERSION, DuckDB::LibraryVersion());
	}
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	auto default_policy = gatekeeper::PolicyValue(gatekeeper::Policy());
	config.AddExtensionOption(POLICY_SETTING, "Global Gatekeeper authorization ceiling", default_policy.type(),
	                          default_policy, SetPolicy, SetScope::GLOBAL);
	// First position: decide replacement scans before any other callback's reader can bind.
	bool installed = false;
	for (auto &scan : config.replacement_scans)
		installed = installed || scan.function == GatekeeperReplacementScan;
	if (!installed)
		config.replacement_scans.insert(config.replacement_scans.begin(), ReplacementScan(GatekeeperReplacementScan));
	ScalarFunction validate("gatekeeper_validate", {LogicalType::VARCHAR}, ResultType(), GatekeeperValidate,
	                        BindOptions);
	validate.varargs = LogicalType::ANY;
	validate.null_handling = FunctionNullHandling::SPECIAL_HANDLING;
	validate.stability = FunctionStability::VOLATILE;
	loader.RegisterFunction(validate);
	TableFunction configure("gatekeeper_configure", {}, Configure, BindConfigure, InitConfigure);
	for (const auto &name : gatekeeper::OptionNames())
		configure.named_parameters[name] = LogicalType::ANY;
	loader.RegisterFunction(configure);
}
void GatekeeperExtension::Load(ExtensionLoader &loader) { LoadInternal(loader); }
std::string GatekeeperExtension::Name() { return "gatekeeper"; }
std::string GatekeeperExtension::Version() const { return "0.1.0"; }
} // namespace duckdb
extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(gatekeeper, loader) { duckdb::LoadInternal(loader); }
}
