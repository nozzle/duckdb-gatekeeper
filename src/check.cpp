#include "check.hpp"
#include "audit.hpp"
#include "authorization.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/type_catalog_entry.hpp"
#include "duckdb/common/enums/logical_operator_type.hpp"
#include "duckdb/function/replacement_scan.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/settings.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/parsed_data/create_type_info.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "duckdb/parser/statement/multi_statement.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/pivotref.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/bound_parameter_map.hpp"
#include "duckdb/planner/logical_operator.hpp"
#include "duckdb/planner/operator/logical_create.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "enforcement.hpp"
#include "engine_errors.hpp"
#include "function_policy.hpp"
#include "json_serializer.hpp"
#include "policy_setting.hpp"

namespace duckdb {
using namespace duckdb_yyjson;

// A dynamic PIVOT (one whose IN list is left to the data) is the one read-only text DuckDB's parser rewrites
// into more than a SELECT (Transformer::CreatePivotStatement): for each such column it emits
//   CREATE OR REPLACE TEMP TYPE "__pivot_enum_<uuid>" AS ENUM (SELECT DISTINCT CAST(col AS VARCHAR) FROM source ...)
// and then the SELECT with that type in the IN list. Gatekeeper admits exactly that CREATE, by shape, so the
// enum is created only from a SELECT the policy allows and only ever in the connection's temporary catalog. The
// shape is the parser's, not a grant of temporary DDL: any other name, catalog, schema, conflict clause, or an
// enum spelled out as literals is an unsupported statement.
static bool PivotEnumName(const string &name) {
	static const string prefix = "__pivot_enum_";
	static const string uuid = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
	if (name.size() != prefix.size() + uuid.size() || name.compare(0, prefix.size(), prefix) != 0)
		return false;
	for (size_t i = 0; i < uuid.size(); i++) {
		auto c = name[prefix.size() + i];
		if (uuid[i] == '-' ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
			return false;
	}
	return true;
}

static bool PivotEnumInfo(const CreateInfo &info) {
	if (info.type != CatalogType::TYPE_ENTRY || !info.temporary || info.internal ||
	    info.on_conflict != OnCreateConflict::REPLACE_ON_CONFLICT)
		return false;
	auto &type = info.Cast<CreateTypeInfo>();
	return type.type.id() == LogicalTypeId::INVALID && PivotEnumName(type.name);
}

// The statement as parsed from text: unqualified, with the SELECT that defines the enum still attached.
static bool PivotEnumStatement(const SQLStatement &statement) {
	if (statement.type != StatementType::CREATE_STATEMENT)
		return false;
	auto &info = *statement.Cast<CreateStatement>().info;
	if (!PivotEnumInfo(info) || !info.catalog.empty() || !info.schema.empty())
		return false;
	auto &query = info.Cast<CreateTypeInfo>().query;
	return query && query->type == StatementType::SELECT_STATEMENT;
}

// The statement as bound: the binder has resolved the temporary catalog and moved the SELECT into the plan as
// the root's single child.
static bool PivotEnumPlan(const LogicalOperator &plan) {
	if (plan.type != LogicalOperatorType::LOGICAL_CREATE_TYPE || plan.children.size() != 1)
		return false;
	auto &info = plan.Cast<LogicalCreate>().info;
	return info && PivotEnumInfo(*info) && info->catalog == TEMP_CATALOG && !info->Cast<CreateTypeInfo>().query;
}

static TextCheck CheckStatementText(ClientContext &context, const gatekeeper::Policy &policy,
                                    const gatekeeper::Policy &ceiling, const string &sql,
                                    const gatekeeper::Limits &limits, bool nested);

// gatekeeper_validate on a dynamic PIVOT decides the statements the engine will run for it, each on the text
// the engine will run (the parser stamps every rewritten statement with its own text, which is what an
// enforced connection's hooks then see), in the engine's order, stopping at the first denial. Only the parser
// produces a batch, and only in this shape: enum types followed by the SELECT that names them. A nested
// dynamic PIVOT puts an earlier enum type in a later enum type's own SELECT, so every statement learns the
// types created before it.
static TextCheck CheckBatchText(ClientContext &context, const gatekeeper::Policy &policy,
                                const gatekeeper::Policy &ceiling, const MultiStatement &batch,
                                const gatekeeper::Limits &limits) {
	TextCheck check;
	auto &statements = batch.statements;
	auto unsupported = [&] {
		check.result = {false, "unsupported", "", "", {{"statement", "only supported read statements are permitted"}}};
		check.units.clear();
		return std::move(check);
	};
	if (statements.size() < 2 || statements.back()->type != StatementType::SELECT_STATEMENT)
		return unsupported();
	for (size_t i = 0; i + 1 < statements.size(); i++)
		if (!PivotEnumStatement(*statements[i]))
			return unsupported();
	gatekeeper::Names enums;
	for (auto &statement : statements) {
		auto part = CheckStatementText(context, policy, ceiling, statement->query, limits, true);
		if (!part.result.allowed) {
			check.result = std::move(part.result);
			return check;
		}
		if (part.units.size() != 1)
			return unsupported();
		check.units.push_back(std::move(part.units[0]));
		check.units.back().pivot_enums = enums;
		if (statement->type == StatementType::CREATE_STATEMENT)
			enums.insert(statement->Cast<CreateStatement>().info->Cast<CreateTypeInfo>().name);
	}
	check.result = {true, "ok"};
	return check;
}

static TextCheck CheckStatementText(ClientContext &context, const gatekeeper::Policy &policy,
                                    const gatekeeper::Policy &ceiling, const string &sql,
                                    const gatekeeper::Limits &limits, bool nested) {
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
	auto &statement = parser.statements[0]; // MAX_STATEMENTS is 1
	if (statement->type == StatementType::MULTI_STATEMENT && !nested)
		return CheckBatchText(context, policy, ceiling, statement->Cast<MultiStatement>(), limits);
	// The SELECT the statement stands for: itself, or the one that defines a dynamic PIVOT's enum type.
	optional_ptr<const SelectStatement> select;
	if (statement->type == StatementType::SELECT_STATEMENT)
		select = &statement->Cast<SelectStatement>();
	else if (PivotEnumStatement(*statement))
		select = &statement->Cast<CreateStatement>().info->Cast<CreateTypeInfo>().query->Cast<SelectStatement>();
	if (!select) {
		check.result = {false, "unsupported", "", "", {{"statement", "only supported read statements are permitted"}}};
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
	yyjson_mut_arr_append(statements,
	                      JsonSerializer::Serialize(*select, doc.get(), true, true, true, serialization_options));
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
	TextCheck::Unit unit;
	check.result = gatekeeper::Validate(yyjson_doc_get_root(ast.get()), policy, &unit.binding, &ceiling, limits);
	if (check.result.allowed) {
		unit.statement = std::move(statement);
		check.units.push_back(std::move(unit));
	}
	return check;
}

TextCheck CheckText(ClientContext &context, const gatekeeper::Policy &policy, const gatekeeper::Policy &ceiling,
                    const string &sql, const gatekeeper::Limits &limits) {
	return CheckStatementText(context, policy, ceiling, sql, limits, false);
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
	// A dynamic PIVOT's enum type: the engine reports it as a statement that creates a temporary object and
	// returns nothing, over the plan of the SELECT that defines it. Its temporary catalog is not a modified
	// database; nothing else may be one either.
	bool pivot_enum = PivotEnumPlan(plan);
	if (!properties.modified_databases.empty())
		deny("statement modifies a database");
	if (properties.return_type != (pivot_enum ? StatementReturnType::NOTHING : StatementReturnType::QUERY_RESULT))
		deny("statement does not return a query result");
	vector<LogicalOperator *> operators{&plan};
	while (!operators.empty()) {
		auto op = operators.back();
		operators.pop_back();
		if (!ReadOperator(op->type) && !(pivot_enum && op == &plan))
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
// this thread and on every enforced connection. The resolved reader is authorized as the caller-written
// table function it stands for when the caller wrote the name, and as a trusted definition's own reader,
// against the deny layer only, when the name is reachable only through a view or macro body.
struct ValidationScope {
	ClientContext &context; // the connection this validation binds on
	const gatekeeper::Policy &policy;
	const gatekeeper::Policy &ceiling;
	const gatekeeper::BindingPolicy &binding; // what the caller wrote, from the text walk
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
	auto gate = scope ? GateMode::ENFORCE : ReplacementGate(context);
	if (gate == GateMode::OPEN)
		return nullptr; // Ordinary connections, and log-only statements already decided, bind as the engine would.
	auto path = ReplacementScan::GetFullPath(input);
	// An enforced connection binding outside Authorize has no request layer and no result in progress: the
	// denial is decided and recorded here, against the statement the connection is executing when there is one.
	// That statement's policy snapshot is the one every check of it must use; only a Prepare() bind, which has
	// no statement in progress, reads the global setting itself. In log-only mode the record is the whole
	// decision: the statement is marked decided so nothing records it again, and the bind continues with the
	// replacement the host callback already produced, so the engine resolves the reader exactly as on an
	// unenforced connection and no callback runs a second time for it.
	auto mode = gate == GateMode::LOG_ONLY ? DecisionMode::LOG_ONLY : DecisionMode::ENFORCE;
	auto record = [&](gatekeeper::Result &result, optional_ptr<const gatekeeper::Policy> in_force) {
		MarkGateDecided(context);
		Decide(context, {mode, Boundary::REPLACEMENT_SCAN, in_force, AdmittedQuery(context)}, result);
		if (mode == DecisionMode::LOG_ONLY)
			return true; // let the engine bind what the callback produced
		throw InternalException("Gatekeeper enforced denial returned"); // Decide throws in ENFORCE mode
	};
	gatekeeper::Policy prepared;
	optional_ptr<const gatekeeper::Policy> enforced;
	// The names the caller wrote, when the statement's text has been walked: under Authorize, the scope's; on an
	// enforced connection binding an admitted statement itself, the record QueryBegin kept. A Prepare() bind
	// outside any statement has no text on record and is pre-screened as though the caller wrote every name.
	optional_ptr<const gatekeeper::BindingPolicy> binding;
	if (scope) {
		binding = &scope->binding;
	} else {
		enforced = AdmittedPolicy(context);
		binding = AdmittedBinding(context);
		if (!enforced) {
			try {
				prepared = GlobalPolicy(context);
				enforced = &prepared;
			} catch (const std::invalid_argument &error) {
				gatekeeper::Result result;
				result.code = "invalid_input";
				result.error_message = string("cannot read the global policy: ") + error.what();
				if (record(result, nullptr))
					return nullptr;
			}
		}
	}
	// A name the caller wrote chooses the reader, so the reader must be allowed like a caller-written table
	// function. A name reachable only through a trusted view or macro body is that definition's reader and
	// passes the deny layer, exactly as the readers such bodies name explicitly do. The callback cannot see
	// which binder asked: a name the caller also wrote is the caller's, query-wide.
	bool caller_written = !binding || binding->caller_table_refs.count(gatekeeper::TableRefPath(
	                                      input.catalog_name, input.schema_name, input.table_name));
	auto reader_permitted = [&](const gatekeeper::Policy &layer, const string &name) {
		return caller_written ? gatekeeper::FunctionAllowed(layer, name) : !gatekeeper::FunctionDenied(layer, name);
	};
	// Returns true when the engine should go on to bind the replacement as produced (log-only); refuses otherwise.
	auto deny = [&](const string &rule, const string &message, const string &function = "") {
		if (!scope) {
			gatekeeper::Result result;
			result.violations.emplace(rule, message, input.catalog_name, input.schema_name, input.table_name, function);
			MarkDenied(result);
			return record(result, enforced);
		}
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
		if (replacement->type != TableReferenceType::TABLE_FUNCTION) {
			if (deny("replacement_scan", "host-language replacement scan cannot be authorized: " + path))
				return replacement;
		}
		auto &function = replacement->Cast<TableFunctionRef>().function;
		if (!function || function->GetExpressionClass() != ExpressionClass::FUNCTION) {
			if (deny("replacement_scan", "replacement scan has no resolvable function: " + path))
				return replacement;
		}
		auto name = function->Cast<FunctionExpression>().function_name;
		vector<const gatekeeper::Policy *> layers;
		if (scope)
			layers = {&scope->ceiling, &scope->policy};
		else
			layers = {enforced.get()};
		for (const auto *layer : layers) {
			if (!reader_permitted(*layer, name)) {
				if (deny("function", "replacement scan function is not allowed: " + gatekeeper::CanonicalFunction(name),
				         gatekeeper::CanonicalFunction(name)))
					return replacement;
			}
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
	// later catalog lookup, so fail closed and let the caller retry. A log-only statement has nothing
	// to protect here and must resolve exactly as an unenforced connection would (autoload retry and
	// FileExists probe included), so it returns to the engine's loop; the callbacks that declined above
	// are asked a second time, which is the one place log-only departs from once-per-lookup.
	if (mode == DecisionMode::LOG_ONLY)
		return nullptr;
	Catalog::GetEntry(context, CatalogType::TABLE_ENTRY, input.catalog_name, input.schema_name, input.table_name);
	throw BinderException("Table \"%s\" appeared during binding; retry validation", path);
}

void InstallReplacementScan(DBConfig &config) {
	for (auto &scan : config.replacement_scans)
		if (scan.function == GatekeeperReplacementScan)
			return;
	config.replacement_scans.insert(config.replacement_scans.begin(), ReplacementScan(GatekeeperReplacementScan));
}

static void AuthorizeStatement(ClientContext &context, const gatekeeper::Policy &policy,
                               const gatekeeper::Policy &ceiling, SQLStatement &statement,
                               const gatekeeper::BindingPolicy &binding,
                               optional_ptr<const case_insensitive_map_t<BoundParameterData>> parameters,
                               gatekeeper::Result &result) {
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
	ValidationScope scope{context, policy, ceiling, binding, result, {}};
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

// The SELECT a unit's statement stands for, where the PIVOTs to substitute live.
static QueryNode &PivotQuery(SQLStatement &statement) {
	if (statement.type == StatementType::SELECT_STATEMENT)
		return *statement.Cast<SelectStatement>().node;
	return *statement.Cast<CreateStatement>().info->Cast<CreateTypeInfo>().query->Cast<SelectStatement>().node;
}

// Values of a host-defined enum a static PIVOT column names, or 1 when the type cannot be read: the bind then
// reports that in the engine's words, for either shape alike.
static idx_t HostEnumSize(ClientContext &context, const string &name) {
	try {
		// The untyped lookup: the typed template names TypeCatalogEntry::Name, which a loadable extension then
		// defines a second time next to the engine's own definition on Linux.
		auto &entry = Catalog::GetEntry(context, CatalogType::TYPE_ENTRY, INVALID_CATALOG, INVALID_SCHEMA, name);
		auto &type = entry.Cast<TypeCatalogEntry>().user_type;
		if (type.id() == LogicalTypeId::ENUM)
			return EnumType::GetSize(type);
	} catch (const CatalogException &) {
	}
	return 1;
}

// Binds the statement of a dynamic PIVOT batch when the enum types it names do not exist yet: every reference
// to one of them becomes an IN list of placeholder values. Binder::BindPivot plans a PIVOT two ways by its
// total number of values, the product over its columns: filtered aggregates up to pivot_filter_threshold, and
// above it a LIST aggregate (with concat for several columns) under a PIVOT operator. The values themselves
// only name output columns, so one bind of each shape authorizes every plan the engine can produce for the
// statement whatever the data holds. The small shape gives each dynamic column one value. The large shape gives
// the first dynamic column of each PIVOT the fewest values that carry the PIVOT's total, static IN lists and
// host enums included, past the threshold while staying under pivot_limit; a PIVOT with no such count has no
// legal LIST plan either and keeps the small shape. Returns whether the large shape differs from the small
// one anywhere. Dynamic columns can sit in any PIVOT of the statement: the FROM clause, a subquery, a CTE, a set
// operand, or a scalar subquery.
static bool SubstitutePivotEnums(ClientContext &context, QueryNode &node, const gatekeeper::Names &enums, bool large) {
	auto threshold = Settings::Get<PivotFilterThresholdSetting>(context);
	auto limit = Settings::Get<PivotLimitSetting>(context);
	bool distinct = false;
	std::function<void(ParsedExpression &)> expression = [&](ParsedExpression &expr) {
		if (expr.GetExpressionClass() == ExpressionClass::SUBQUERY)
			distinct |= SubstitutePivotEnums(context, *expr.Cast<SubqueryExpression>().subquery->node, enums, large);
		ParsedExpressionIterator::EnumerateChildren(expr, expression);
	};
	ParsedExpressionIterator::EnumerateQueryNodeChildren(
	    node,
	    [&](unique_ptr<ParsedExpression> &child) {
		    if (child)
			    expression(*child);
	    },
	    [&](TableRef &ref) {
		    if (ref.type != TableReferenceType::PIVOT)
			    return;
		    auto &pivots = ref.Cast<PivotRef>().pivots;
		    vector<reference<PivotColumn>> dynamic;
		    // The PIVOT's values before the dynamic columns contribute. Saturates at the limit: past it no LIST
		    // plan is legal whatever the dynamic columns add, and the engine rejects the small shape too. Zero
		    // (an empty host enum) stays zero: the PIVOT has no values at all and no large shape.
		    idx_t fixed = 1;
		    auto multiply = [&](idx_t values) {
			    if (fixed == 0 || values == 0)
				    fixed = 0;
			    else if (values > limit / fixed)
				    fixed = limit;
			    else
				    fixed *= values;
		    };
		    for (auto &column : pivots) {
			    if (!column.pivot_enum.empty() && enums.count(column.pivot_enum))
				    dynamic.emplace_back(column);
			    else if (!column.entries.empty())
				    multiply(column.entries.size());
			    else if (!column.pivot_enum.empty())
				    multiply(HostEnumSize(context, column.pivot_enum));
		    }
		    if (dynamic.empty())
			    return;
		    idx_t count = 1;
		    if (large && fixed > 0 && fixed <= threshold && limit > 0) {
			    // The fewest values that carry fixed * candidate past the threshold, taken only when that total
			    // also stays under the limit; both comparisons are arranged so neither product can overflow.
			    auto candidate = threshold / fixed + 1;
			    if (candidate > 0 && candidate <= (limit - 1) / fixed)
				    count = candidate;
		    }
		    distinct |= count > 1;
		    for (auto &column : dynamic) {
			    column.get().pivot_enum.clear();
			    for (idx_t i = 0; i < count; i++) {
				    PivotColumnEntry entry;
				    entry.alias = std::to_string(i);
				    for (size_t n = 0; n < column.get().pivot_expressions.size(); n++)
					    entry.values.emplace_back(entry.alias);
				    column.get().entries.push_back(std::move(entry));
			    }
			    count = 1;
		    }
	    });
	return distinct;
}

void Authorize(ClientContext &context, const gatekeeper::Policy &policy, const gatekeeper::Policy &ceiling,
               TextCheck::Unit &unit, optional_ptr<const case_insensitive_map_t<BoundParameterData>> parameters,
               gatekeeper::Result &result) {
	if (unit.pivot_enums.empty()) {
		if (unit.statement->type == StatementType::SELECT_STATEMENT)
			return AuthorizeStatement(context, policy, ceiling, *unit.statement, unit.binding, parameters, result);
		// Binder::Bind moves a CreateStatement's definition into the plan; keep the admitted statement intact.
		auto copy = unit.statement->Copy();
		return AuthorizeStatement(context, policy, ceiling, *copy, unit.binding, parameters, result);
	}
	for (bool large : {false, true}) {
		auto copy = unit.statement->Copy();
		if (!SubstitutePivotEnums(context, PivotQuery(*copy), unit.pivot_enums, large) && large)
			break;
		AuthorizeStatement(context, policy, ceiling, *copy, unit.binding, parameters, result);
	}
}

bool DescribeError(const ErrorData &data, bool binding, gatekeeper::Result &result) {
	switch (data.Type()) {
	case ExceptionType::PARSER: {
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
		return true;
	}
	case ExceptionType::INVALID_INPUT:
		result.code = binding ? "binding" : "invalid_input";
		if (binding)
			result.error_type = "Invalid Input";
		result.error_message = data.RawMessage();
		return true;
	default:
		break;
	}
	if (gatekeeper::PropagateEngineError(data.Type()))
		return false;
	result.code = gatekeeper::EngineErrorCode(binding);
	result.error_type = Exception::ExceptionTypeToString(data.Type());
	result.error_message = data.RawMessage();
	if (data.Type() == ExceptionType::PARAMETER_NOT_RESOLVED)
		result.error_message = "Validation cannot complete binding without parameter values or types";
	return true;
}

bool DescribeError(const std::exception &error, bool binding, gatekeeper::Result &result) {
	if (auto invalid = dynamic_cast<const std::invalid_argument *>(&error)) {
		result.code = binding ? "binding" : "invalid_input";
		result.error_message = invalid->what();
		return true;
	}
	if (dynamic_cast<const std::bad_alloc *>(&error))
		return false;
	return DescribeError(ErrorData(error), binding, result);
}

gatekeeper::Result Check(ClientContext &context, const gatekeeper::Policy &policy, const gatekeeper::Policy &ceiling,
                         const string &sql, const gatekeeper::Limits &limits) {
	gatekeeper::Result result;
	bool binding = false;
	try {
		auto text = CheckText(context, policy, ceiling, sql, limits);
		binding = true;
		// The engine runs a batch in order and stops at the first statement that fails, so the statements
		// admitted before a denied one bind first: a bind that fails among them is the decision, as it would
		// be the engine's error, and only if they all pass is the later text denial reported.
		for (auto &unit : text.units)
			Authorize(context, policy, ceiling, unit, nullptr, result);
		if (!text.result.allowed)
			return text.result;
		result.allowed = true;
		result.code = "ok";
		return result;
	} catch (const std::exception &error) {
		if (!DescribeError(error, binding, result))
			throw;
	}
	MarkDenied(result);
	return result;
}

void MarkDenied(gatekeeper::Result &result) {
	result.allowed = false;
	if (!result.violations.empty()) {
		result.code = "forbidden";
		result.error_type.clear();
		result.error_message.clear();
	}
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
