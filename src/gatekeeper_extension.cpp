#define DUCKDB_EXTENSION_MAIN
#include "gatekeeper_extension.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/function/pragma_function.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "json_serializer.hpp"
#include "validator.hpp"
#include <mutex>

namespace duckdb {
using namespace duckdb_yyjson;

static LogicalType ResultType() {
	return LogicalType::STRUCT({{"allowed", LogicalType::BOOLEAN},
	                            {"code", LogicalType::VARCHAR},
	                            {"violations", LogicalType::LIST(LogicalType::VARCHAR)},
	                            {"error_type", LogicalType::VARCHAR},
	                            {"error_message", LogicalType::VARCHAR}});
}

static Value ResultValue(const gatekeeper::Result &result) {
	vector<Value> violations;
	for (auto &message : result.violations)
		violations.emplace_back(message);
	return Value::STRUCT(ResultType(), {Value::BOOLEAN(result.allowed), Value(result.code),
	                                    Value::LIST(LogicalType::VARCHAR, violations), Value(result.error_type),
	                                    Value(result.error_message)});
}

struct GatekeeperState : ScalarFunctionInfo {
	std::mutex mutex;
	bool configured = false;
	gatekeeper::Policy defaults;
	GatekeeperState() : defaults(nullptr) {}
};

static gatekeeper::Result Check(ClientContext &context, const gatekeeper::Policy &defaults, const string &sql,
                                const string &options) {
	gatekeeper::Result result;
	try {
		if (options.size() > 1048576)
			throw InvalidInputException("options exceed 1 MiB");
		unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> policy_doc(yyjson_read(options.data(), options.size(), 0),
		                                                              yyjson_doc_free);
		if (!policy_doc)
			throw InvalidInputException("options must be valid JSON");
		auto policy = defaults;
		policy.Apply(yyjson_doc_get_root(policy_doc.get()));
		if (sql.find('\0') != string::npos)
			throw InvalidInputException("SQL contains a NUL byte");
		if (sql.size() > policy.bytes)
			throw InvalidInputException("SQL exceeds max_ast_bytes input bound");
		Parser parser;
		parser.ParseQuery(sql);
		if (parser.statements.empty() || parser.statements.size() > policy.statements) {
			return {false, "forbidden", "", "", {"statement count exceeds policy or SQL is empty"}};
		}
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
			if (statement->type != StatementType::SELECT_STATEMENT) {
				return {false, "unsupported", "", "", {"only supported read statements are permitted"}};
			}
			auto node = JsonSerializer::Serialize(statement->Cast<SelectStatement>(), doc.get(), true, true, true);
			yyjson_mut_arr_append(statements, node);
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
			return {false, "forbidden", "", "", {"serialized AST exceeds max_ast_bytes"}};
		auto preflight_policy = policy;
		if (policy.resolve_objects) {
			// Missing qualifiers must be authorized after binding, against the resolved identity.
			preflight_policy.defer_table_checks = true;
		}
		result = gatekeeper::Validate(yyjson_doc_get_root(ast.get()), preflight_policy);
		if (!result.allowed || !policy.resolve_objects)
			return result;
		for (auto &statement : parser.statements) {
			auto binder = Binder::CreateBinder(context);
			binder->SetCatalogLookupCallback([&](CatalogEntry &entry) {
				if (entry.type != CatalogType::TABLE_ENTRY)
					return;
				auto &table = entry.Cast<TableCatalogEntry>();
				auto catalog = table.schema.catalog.GetName();
				auto schema = table.schema.name;
				auto name = table.name;
				if (policy.catalogs && !policy.allowed_catalogs.count(catalog))
					result.violations.insert("catalog is not allowed: " + catalog);
				if (policy.schemas && !policy.allowed_schemas.count(schema))
					result.violations.insert("schema is not allowed: " + schema);
				if (policy.tables && !policy.allowed_tables.count({catalog, schema, name}) &&
				    !policy.allowed_tables.count({"", schema, name}))
					result.violations.insert("table is not allowed: " + catalog + "." + schema + "." + name);
				if (!result.violations.empty())
					throw PermissionException("resolved object is not allowed");
			});
			try {
				auto bound = binder->Bind(*statement);
			} catch (const PermissionException &) {
				if (result.violations.empty())
					throw;
				result.allowed = false;
				result.code = "forbidden";
				return result;
			}
		}
		return result;
	} catch (const ParserException &error) {
		ErrorData data(error);
		result.code = "parser";
		result.error_type = "parser";
		result.error_message = data.RawMessage();
	} catch (const std::invalid_argument &error) {
		result.code = "invalid_input";
		result.error_message = error.what();
	} catch (const InvalidInputException &error) {
		result.code = "invalid_input";
		result.error_message = ErrorData(error).RawMessage();
	} catch (const Exception &error) {
		result.allowed = false;
		result.code = "binding";
		ErrorData data(error);
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
	auto &function = state.expr.Cast<BoundFunctionExpression>().function;
	auto &configuration = function.function_info->Cast<GatekeeperState>();
	gatekeeper::Policy defaults(nullptr);
	{
		std::lock_guard<std::mutex> lock(configuration.mutex);
		defaults = configuration.defaults;
	}
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto sql = args.data[0].GetValue(row);
		auto options = args.ColumnCount() == 2 ? args.data[1].GetValue(row) : Value("{}");
		if (sql.IsNull() || options.IsNull()) {
			result.SetValue(row, ResultValue({false, "invalid_input", "", "NULL input", {}}));
		} else {
			result.SetValue(row, ResultValue(Check(state.GetContext(), defaults, sql.GetValue<string>(),
			                                       options.GetValue<string>())));
		}
	}
}

static void LoadInternal(ExtensionLoader &loader) {
	auto configuration = make_shared_ptr<GatekeeperState>();
	ScalarFunctionSet functions("gatekeeper_validate");
	for (auto parameters :
	     {vector<LogicalType>{LogicalType::VARCHAR}, vector<LogicalType>{LogicalType::VARCHAR, LogicalType::VARCHAR}}) {
		ScalarFunction function(parameters, ResultType(), GatekeeperValidate);
		function.null_handling = FunctionNullHandling::SPECIAL_HANDLING;
		function.stability = FunctionStability::VOLATILE;
		function.function_info = configuration;
		functions.AddFunction(function);
	}
	loader.RegisterFunction(functions);
	ScalarFunction configure(
	    "gatekeeper_configure", {LogicalType::VARCHAR}, LogicalType::BOOLEAN,
	    [](DataChunk &args, ExpressionState &state, Vector &result) {
		    auto &config = state.expr.Cast<BoundFunctionExpression>().function.function_info->Cast<GatekeeperState>();
		    if (args.size() != 1)
			    throw InvalidInputException("gatekeeper_configure requires one row");
		    auto input = args.data[0].GetValue(0);
		    if (input.IsNull())
			    throw InvalidInputException("NULL configuration");
		    auto text = input.GetValue<string>();
		    if (text.size() > 1048576)
			    throw InvalidInputException("configuration exceeds 1 MiB");
		    unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> doc(yyjson_read(text.data(), text.size(), 0),
			                                                       yyjson_doc_free);
		    if (!doc)
			    throw InvalidInputException("configuration must be valid JSON");
		    try {
			    gatekeeper::Policy policy(yyjson_doc_get_root(doc.get()));
			    std::lock_guard<std::mutex> lock(config.mutex);
			    if (config.configured)
				    throw InvalidInputException("Gatekeeper defaults are already configured");
			    config.defaults = std::move(policy);
			    config.configured = true;
		    } catch (const std::invalid_argument &error) {
			    throw InvalidInputException(error.what());
		    }
		    result.SetValue(0, Value::BOOLEAN(true));
	    });
	configure.null_handling = FunctionNullHandling::SPECIAL_HANDLING;
	configure.stability = FunctionStability::VOLATILE;
	configure.function_info = configuration;
	loader.RegisterFunction(configure);
}

void GatekeeperExtension::Load(ExtensionLoader &loader) { LoadInternal(loader); }
std::string GatekeeperExtension::Name() { return "gatekeeper"; }
std::string GatekeeperExtension::Version() const { return "0.1.0"; }
} // namespace duckdb

extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(gatekeeper, loader) { duckdb::LoadInternal(loader); }
}
