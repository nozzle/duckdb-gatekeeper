#include "check.hpp"
#include "authorization.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/enums/logical_operator_type.hpp"
#include "duckdb/function/replacement_scan.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/bound_parameter_map.hpp"
#include "duckdb/planner/logical_operator.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "enforcement.hpp"
#include "engine_errors.hpp"
#include "function_policy.hpp"
#include "json_serializer.hpp"
#include "policy_setting.hpp"

namespace duckdb {
using namespace duckdb_yyjson;

TextCheck CheckText(ClientContext &context, const gatekeeper::Policy &policy, const gatekeeper::Policy &ceiling,
                    const string &sql, const gatekeeper::Limits &limits) {
	TextCheck check;
	if (sql.find('\0') != string::npos)
		throw InvalidInputException("SQL contains a NUL byte");
	if (sql.size() > limits.bytes) {
		check.result = {false, "forbidden", "", "", {{"limit", "SQL exceeds fixed input size limit"}}};
		return check;
	}
	Parser parser(context.GetParserOptions());
	parser.ParseQuery(sql);
	if (parser.statements.empty())
		throw InvalidInputException("SQL contains no statements");
	if (parser.statements.size() > gatekeeper::MAX_STATEMENTS) {
		check.result = {false, "forbidden", "", "", {{"limit", "statement count exceeds fixed limit"}}};
		return check;
	}
	unique_ptr<yyjson_mut_doc, decltype(&yyjson_mut_doc_free)> doc(yyjson_mut_doc_new(nullptr), yyjson_mut_doc_free);
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
		if (statement->type != StatementType::SELECT_STATEMENT) {
			check.result = {
			    false, "unsupported", "", "", {{"statement", "only supported read statements are permitted"}}};
			return check;
		}
		yyjson_mut_arr_append(statements, JsonSerializer::Serialize(statement->Cast<SelectStatement>(), doc.get(), true,
		                                                            true, true, serialization_options));
	}
	unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> ast(yyjson_mut_doc_imut_copy(doc.get(), nullptr),
	                                                       yyjson_doc_free);
	if (!ast)
		throw std::bad_alloc();
	size_t bytes = 0;
	unique_ptr<char, decltype(&free)> serialized(yyjson_write(ast.get(), 0, &bytes), free);
	if (!serialized)
		throw std::bad_alloc();
	if (bytes > limits.bytes) {
		check.result = {false, "forbidden", "", "", {{"limit", "serialized AST exceeds fixed size limit"}}};
		return check;
	}
	check.result = gatekeeper::Validate(yyjson_doc_get_root(ast.get()), policy, &check.binding, &ceiling, limits);
	if (check.result.allowed)
		check.statements = std::move(parser.statements);
	return check;
}

// Plan operators a bound SELECT can contain before the optimizer runs, reviewed against
// duckdb/common/enums/logical_operator_type.hpp. Everything else, including operators added by a
// future engine, is denied: this is the plan-level twin of the grammar allowlist, and it is what keeps
// a plan that did not come from validated text (a relation, a deserialized plan) read-only.
static bool ReadOperator(LogicalOperatorType type) {
	switch (type) {
	case LogicalOperatorType::LOGICAL_PROJECTION:
	case LogicalOperatorType::LOGICAL_FILTER:
	case LogicalOperatorType::LOGICAL_AGGREGATE_AND_GROUP_BY:
	case LogicalOperatorType::LOGICAL_WINDOW:
	case LogicalOperatorType::LOGICAL_UNNEST:
	case LogicalOperatorType::LOGICAL_LIMIT:
	case LogicalOperatorType::LOGICAL_ORDER_BY:
	case LogicalOperatorType::LOGICAL_TOP_N:
	case LogicalOperatorType::LOGICAL_DISTINCT:
	case LogicalOperatorType::LOGICAL_SAMPLE:
	case LogicalOperatorType::LOGICAL_PIVOT:
	case LogicalOperatorType::LOGICAL_GET:
	case LogicalOperatorType::LOGICAL_CHUNK_GET: // DESCRIBE of a query materializes its column list
	case LogicalOperatorType::LOGICAL_DELIM_GET:
	case LogicalOperatorType::LOGICAL_EXPRESSION_GET:
	case LogicalOperatorType::LOGICAL_DUMMY_SCAN:
	case LogicalOperatorType::LOGICAL_EMPTY_RESULT:
	case LogicalOperatorType::LOGICAL_CTE_REF:
	case LogicalOperatorType::LOGICAL_JOIN:
	case LogicalOperatorType::LOGICAL_DELIM_JOIN:
	case LogicalOperatorType::LOGICAL_COMPARISON_JOIN:
	case LogicalOperatorType::LOGICAL_ANY_JOIN:
	case LogicalOperatorType::LOGICAL_CROSS_PRODUCT:
	case LogicalOperatorType::LOGICAL_POSITIONAL_JOIN:
	case LogicalOperatorType::LOGICAL_ASOF_JOIN:
	case LogicalOperatorType::LOGICAL_DEPENDENT_JOIN:
	case LogicalOperatorType::LOGICAL_UNION:
	case LogicalOperatorType::LOGICAL_EXCEPT:
	case LogicalOperatorType::LOGICAL_INTERSECT:
	case LogicalOperatorType::LOGICAL_RECURSIVE_CTE:
	case LogicalOperatorType::LOGICAL_MATERIALIZED_CTE:
		return true;
	default:
		return false;
	}
}

void CheckPlan(const gatekeeper::Policy &policy, const gatekeeper::Policy &ceiling,
               const gatekeeper::BindingPolicy &binding, const StatementProperties &properties, LogicalOperator &plan,
               gatekeeper::Result &result) {
	auto deny = [&](const string &message) {
		result.violations.emplace("statement", message);
		throw PermissionException("only supported read statements are permitted");
	};
	if (!properties.modified_databases.empty())
		deny("statement modifies a database");
	if (properties.return_type != StatementReturnType::QUERY_RESULT)
		deny("statement does not return a query result");
	vector<LogicalOperator *> operators{&plan};
	while (!operators.empty()) {
		auto op = operators.back();
		operators.pop_back();
		if (!ReadOperator(op->type))
			deny("unsupported plan operator: " + LogicalOperatorToString(op->type));
		// Base tables the plan actually scans are authorized by resolved identity here as well as in the
		// private bind's catalog callback, so a plan that did not come from that bind (a relation whose SQL
		// rendering diverged from its query node) still cannot read a table the policy denies. Views are
		// inlined by now and remain the callback's responsibility.
		if (op->type == LogicalOperatorType::LOGICAL_GET) {
			auto table = op->Cast<LogicalGet>().GetTable();
			if (table) {
				AuthorizeObject(ceiling, binding, *table, result);
				AuthorizeObject(policy, binding, *table, result);
			}
		}
		for (auto &child : op->children)
			operators.push_back(child.get());
	}
	AuthorizePlan(ceiling, binding, plan, result);
	AuthorizePlan(policy, binding, plan, result);
}

// Replacement scans run when a table name resolves to no catalog object. DuckDB's callbacks only
// construct a TableRef; the reader binds (and may open files) afterwards. Gatekeeper installs the
// first callback at LOAD and decides before that bind happens, both while Authorize is binding on
// this thread and on every enforced connection: the resolved reader is authorized like a caller-written
// table function in every applicable policy layer.
struct ValidationScope {
	ClientContext &context; // the connection this validation binds on
	const gatekeeper::Policy &policy;
	const gatekeeper::Policy &ceiling;
	gatekeeper::Result &result;
	gatekeeper::Names authorized; // table names admitted through replacement, case-folded
};
static thread_local ValidationScope *active_scope = nullptr;
// Nested validations (a host callback validating on another connection) restore the outer scope.
struct ScopeGuard {
	ValidationScope *previous;
	explicit ScopeGuard(ValidationScope &scope) : previous(active_scope) { active_scope = &scope; }
	~ScopeGuard() { active_scope = previous; }
};

static unique_ptr<TableRef> GatekeeperReplacementScan(ClientContext &context, ReplacementScanInput &input,
                                                      optional_ptr<ReplacementScanData>) {
	auto scope = active_scope;
	if (scope && &context != &scope->context)
		scope = nullptr; // A reentrant connection on this thread is not the one being validated.
	if (!scope && !IsEnforced(context))
		return nullptr; // Ordinary connections are unaffected.
	auto path = ReplacementScan::GetFullPath(input);
	// An enforced connection binding outside Authorize has no request layer or result to record into.
	gatekeeper::Policy enforced;
	if (!scope) {
		try {
			enforced = GlobalPolicy(context);
		} catch (const std::invalid_argument &error) {
			throw PermissionException(string("Gatekeeper cannot read the global policy: ") + error.what());
		}
	}
	auto deny = [&](const string &rule, const string &message, const string &function = "") {
		if (!scope)
			throw PermissionException("Gatekeeper denied this statement: " + rule + ": " + message);
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
		if (replacement->type != TableReferenceType::TABLE_FUNCTION)
			deny("replacement_scan", "host-language replacement scan cannot be authorized: " + path);
		auto &function = replacement->Cast<TableFunctionRef>().function;
		if (!function || function->GetExpressionClass() != ExpressionClass::FUNCTION)
			deny("replacement_scan", "replacement scan has no resolvable function: " + path);
		auto name = function->Cast<FunctionExpression>().function_name;
		vector<const gatekeeper::Policy *> layers;
		if (scope)
			layers = {&scope->ceiling, &scope->policy};
		else
			layers = {&enforced};
		for (const auto *layer : layers) {
			if (!gatekeeper::FunctionAllowed(*layer, name))
				deny("function", "replacement scan function is not allowed: " + gatekeeper::CanonicalFunction(name),
				     gatekeeper::CanonicalFunction(name));
		}
		if (scope) {
			scope->authorized.insert(gatekeeper::Lower(input.table_name));
			scope->result.objects.insert({"", "", path, "replacement"});
		}
		return replacement;
	}
	// No callback claimed the name. Returning nullptr would let DuckDB run every callback a second
	// time outside this authorization, so raise the engine's own missing-table error here instead.
	// The lookup throws for every catalog with transactional DDL. If a catalog without it finds the
	// entry after all, returning nullptr would still resume DuckDB's callback loop rather than the
	// later catalog lookup, so fail closed and let the caller retry.
	Catalog::GetEntry(context, CatalogType::TABLE_ENTRY, input.catalog_name, input.schema_name, input.table_name);
	throw BinderException("Table \"%s\" appeared during binding; retry validation", path);
}

void InstallReplacementScan(DBConfig &config) {
	for (auto &scan : config.replacement_scans)
		if (scan.function == GatekeeperReplacementScan)
			return;
	config.replacement_scans.insert(config.replacement_scans.begin(), ReplacementScan(GatekeeperReplacementScan));
}

void Authorize(ClientContext &context, const gatekeeper::Policy &policy, const gatekeeper::Policy &ceiling,
               SQLStatement &statement, const gatekeeper::BindingPolicy &binding,
               optional_ptr<const case_insensitive_map_t<BoundParameterData>> parameters, gatekeeper::Result &result) {
	case_insensitive_map_t<BoundParameterData> parameter_data;
	if (parameters)
		parameter_data = *parameters;
	BoundParameterMap bound_parameters(parameter_data);
	auto binder = Binder::CreateBinder(context);
	binder->SetParameters(bound_parameters);
	binder->SetBindingMode(BindingMode::EXTRACT_REPLACEMENT_SCANS);
	binder->SetCatalogLookupCallback([&](CatalogEntry &entry) {
		AuthorizeObject(ceiling, binding, entry, result);
		AuthorizeObject(policy, binding, entry, result);
	});
	ValidationScope scope{context, policy, ceiling, result, {}};
	BoundStatement bound;
	{
		ScopeGuard guard(scope);
		bound = binder->Bind(statement);
	}
	// Unlike Planner::CreatePlan, never turn ParameterNotResolved into a partial success.
	// parameters.rebind is a cache hint, not incomplete binding.
	if (!bound.plan)
		throw BinderException("Validation requires a complete bound plan; parameter values or types may be needed");
	// Some bind callbacks return placeholder plans instead of throwing ParameterNotResolved.
	// Mirror Planner's bound_all_parameters type check: execution must not choose a different
	// implementation after validation by resolving an UNKNOWN parameter for the first time.
	for (const auto &entry : bound_parameters.GetParameters())
		if (!entry.second->return_type.IsValid())
			throw BinderException("Validation requires a complete bound plan; parameter values or types may be needed");
	CheckPlan(policy, ceiling, binding, binder->GetStatementProperties(), *bound.plan, result);
	// Backstop: every replacement DuckDB recorded must have passed the Gatekeeper callback.
	for (auto &entry : binder->GetReplacementScans())
		if (!scope.authorized.count(gatekeeper::Lower(entry.first)))
			result.violations.emplace("replacement_scan", "replacement scan was not authorized: " + entry.first, "", "",
			                          entry.first);
	if (!result.violations.empty())
		throw PermissionException("unauthorized replacement scan");
}

gatekeeper::Result Check(ClientContext &context, const gatekeeper::Policy &policy, const gatekeeper::Policy &ceiling,
                         const string &sql, const gatekeeper::Limits &limits) {
	gatekeeper::Result result;
	bool binding = false;
	try {
		auto text = CheckText(context, policy, ceiling, sql, limits);
		if (!text.result.allowed)
			return text.result;
		result = std::move(text.result);
		binding = true;
		for (auto &statement : text.statements)
			Authorize(context, policy, ceiling, *statement, text.binding, nullptr, result);
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

string DenialMessage(const gatekeeper::Result &result) {
	string message = "Gatekeeper denied this statement";
	if (!result.code.empty() && result.code != "forbidden")
		message += " (" + result.code + ")";
	string details;
	for (const auto &violation : result.violations) {
		if (!details.empty())
			details += "; ";
		details += violation.rule + ": " + violation.message;
	}
	if (details.empty() && !result.error_message.empty())
		details = result.error_message;
	if (!details.empty())
		message += ": " + details;
	return message;
}
} // namespace duckdb
