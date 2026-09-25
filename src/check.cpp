#include "check.hpp"
#include "audit.hpp"
#include "authorization.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/scalar_macro_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/type_catalog_entry.hpp"
#include "duckdb/catalog/standard_entry.hpp"
#include "duckdb/common/enums/logical_operator_type.hpp"
#include "duckdb/function/replacement_scan.hpp"
#include "duckdb/function/scalar_macro_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/settings.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/parsed_data/create_type_info.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "duckdb/parser/statement/multi_statement.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/emptytableref.hpp"
#include "duckdb/parser/tableref/pivotref.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/bound_parameter_map.hpp"
#include "duckdb/planner/logical_operator.hpp"
#include "duckdb/planner/operator/logical_create.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "enforcement.hpp"
#include "engine_api.hpp"
#include "engine_errors.hpp"
#include "function_policy.hpp"
#include "json_serializer.hpp"
#include "policy_setting.hpp"

namespace duckdb {
using namespace duckdb_yyjson;
using Doc = unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)>;

// A SELECT as the binding boundary reads it: DuckDB's own JSON serialization at the latest compatibility, in the
// shape json_serialize_sql produces, copied into the immutable form the grammar walk reads.
static Doc SerializeStatement(const SelectStatement &select) {
	unique_ptr<yyjson_mut_doc, decltype(&yyjson_mut_doc_free)> doc(yyjson_mut_doc_new(nullptr), yyjson_mut_doc_free);
	if (!doc)
		throw std::bad_alloc();
	auto root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	yyjson_mut_obj_add_false(doc.get(), root, "error");
	auto statements = yyjson_mut_arr(doc.get());
	yyjson_mut_obj_add_val(doc.get(), root, "statements", statements);
	yyjson_mut_arr_append(
	    statements, JsonSerializer::Serialize(select, doc.get(), true, true, true, engine::LatestSerialization()));
	Doc ast(yyjson_mut_doc_imut_copy(doc.get(), nullptr), yyjson_doc_free);
	if (!ast)
		throw std::bad_alloc();
	return ast;
}

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
	return type.type.id() == LogicalTypeId::INVALID && PivotEnumName(engine::TypeName(type));
}

// The statement as parsed from text: unqualified, with the SELECT that defines the enum still attached.
static bool PivotEnumStatement(const SQLStatement &statement) {
	if (statement.type != StatementType::CREATE_STATEMENT)
		return false;
	auto &info = *statement.Cast<CreateStatement>().info;
	if (!PivotEnumInfo(info) || !engine::InfoCatalog(info).empty() || !engine::InfoSchema(info).empty())
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
	return info && PivotEnumInfo(*info) && engine::InfoCatalog(*info) == TEMP_CATALOG &&
	       !info->Cast<CreateTypeInfo>().query;
}

TextCheck::Unit TextCheck::Unit::Unattributed() {
	Unit unit;
	unit.provenance.unattributed = true;
	return unit;
}

static TextCheck CheckStatementText(ClientContext &context, const gatekeeper::Layers &layers, const string &sql,
                                    const gatekeeper::Limits &limits, bool nested);

// gatekeeper_validate on a dynamic PIVOT decides the statements the engine will run for it, each on the text
// the engine will run (the parser stamps every rewritten statement with its own text, which is what an
// enforced connection's hooks then see), in the engine's order, stopping at the first denial. Only the parser
// produces a batch, and only in this shape: enum types followed by the SELECT that names them. A nested
// dynamic PIVOT puts an earlier enum type in a later enum type's own SELECT, so every statement learns the
// types created before it.
static TextCheck CheckBatchText(ClientContext &context, const gatekeeper::Layers &layers, const MultiStatement &batch,
                                const gatekeeper::Limits &limits) {
	TextCheck check;
	auto &statements = batch.statements;
	auto unsupported = [&] {
		check.result = gatekeeper::UnsupportedStatement();
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
		auto part = CheckStatementText(context, layers, statement->query, limits, true);
		if (!part.result.allowed) {
			check.result = std::move(part.result);
			return check;
		}
		if (part.units.size() != 1)
			return unsupported();
		check.units.push_back(std::move(part.units[0]));
		check.units.back().pivot_enums = enums;
		if (statement->type == StatementType::CREATE_STATEMENT)
			enums.insert(engine::TypeName(statement->Cast<CreateStatement>().info->Cast<CreateTypeInfo>()));
	}
	check.result = {true, gatekeeper::codes::OK};
	return check;
}

static TextCheck CheckStatementText(ClientContext &context, const gatekeeper::Layers &layers, const string &sql,
                                    const gatekeeper::Limits &limits, bool nested) {
	TextCheck check;
	if (sql.find('\0') != string::npos)
		throw InvalidInputException("SQL contains a NUL byte");
	if (sql.size() > limits.bytes) {
		check.result = gatekeeper::FixedLimitExceeded("SQL exceeds fixed input size limit");
		return check;
	}
	Parser parser(context.GetParserOptions());
	parser.ParseQuery(sql);
	if (parser.statements.empty())
		throw InvalidInputException("SQL contains no statements");
	if (parser.statements.size() > gatekeeper::MAX_STATEMENTS) {
		check.result = gatekeeper::FixedLimitExceeded("statement count exceeds fixed limit");
		return check;
	}
	auto &statement = parser.statements[0]; // MAX_STATEMENTS is 1
	if (statement->type == StatementType::MULTI_STATEMENT && !nested)
		return CheckBatchText(context, layers, statement->Cast<MultiStatement>(), limits);
	// The SELECT the statement stands for: itself, or the one that defines a dynamic PIVOT's enum type.
	optional_ptr<const SelectStatement> select;
	if (statement->type == StatementType::SELECT_STATEMENT)
		select = &statement->Cast<SelectStatement>();
	else if (PivotEnumStatement(*statement))
		select = &statement->Cast<CreateStatement>().info->Cast<CreateTypeInfo>().query->Cast<SelectStatement>();
	if (!select) {
		check.result = gatekeeper::UnsupportedStatement();
		return check;
	}
	auto ast = SerializeStatement(*select);
	size_t bytes = 0;
	unique_ptr<char, decltype(&free)> serialized(yyjson_write(ast.get(), 0, &bytes), free);
	if (!serialized)
		throw std::bad_alloc();
	if (bytes > limits.bytes) {
		check.result = gatekeeper::FixedLimitExceeded("serialized AST exceeds fixed size limit");
		return check;
	}
	TextCheck::Unit unit;
	check.result =
	    gatekeeper::Validate(yyjson_doc_get_root(ast.get()), layers.policy, &unit.binding, &layers.ceiling, limits);
	if (check.result.allowed) {
		unit.statement = std::move(statement);
		check.units.push_back(std::move(unit));
	}
	return check;
}

TextCheck CheckText(ClientContext &context, const gatekeeper::Layers &layers, const string &sql,
                    const gatekeeper::Limits &limits) {
	return CheckStatementText(context, layers, sql, limits, false);
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
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	case LogicalOperatorType::LOGICAL_SECURE_VIEW:
		// Read-only wrapper over the expanded view. Traverse its child for authorization and scan
		// accounting; never remove or rewrite DuckDB's optimization/statistics boundary.
#endif
		return true;
	default:
		return false;
	}
}

void CheckPlan(const gatekeeper::Layers &layers, TextCheck::Unit &unit, PlanOrigin origin,
               const StatementProperties &properties, LogicalOperator &plan, gatekeeper::Result &result) {
	auto deny = [&](const string &message) {
		result.violations.emplace(gatekeeper::rules::STATEMENT, message);
		throw PermissionException(gatekeeper::UNSUPPORTED_STATEMENT);
	};
	// A dynamic PIVOT's enum type: the engine reports it as a statement that creates a temporary object and
	// returns nothing, over the plan of the SELECT that defines it. Its temporary catalog is not a modified
	// database; nothing else may be one either.
	bool pivot_enum = PivotEnumPlan(plan);
	if (!properties.modified_databases.empty())
		deny("statement modifies a database");
	if (properties.return_type != (pivot_enum ? StatementReturnType::NOTHING : StatementReturnType::QUERY_RESULT))
		deny("statement does not return a query result");
	auto &provenance = unit.provenance;
	if (origin == PlanOrigin::PRIVATE) {
		provenance.validated_scans.clear();
		provenance.validated_function_scans.clear();
	}
	auto remaining = provenance.validated_scans;
	auto remaining_functions = provenance.validated_function_scans;
	// One scan of the engine's plan against the private bind's record: recorded by the private pass, consumed by
	// the engine pass, which refuses a source the record holds fewer times than the plan scans it, never included.
	auto account = [&](auto &recorded, auto &left, const auto &key, const gatekeeper::Violation &divergence) {
		if (origin == PlanOrigin::PRIVATE) {
			recorded[key]++;
		} else if (left[key] == 0) {
			result.violations.insert(divergence);
			throw PermissionException("plan diverged from the validated statement");
		} else {
			left[key]--;
		}
	};
	vector<LogicalOperator *> operators{&plan};
	while (!operators.empty()) {
		auto op = operators.back();
		operators.pop_back();
		if (!ReadOperator(op->type) && !(pivot_enum && op == &plan))
			deny("unsupported plan operator: " + LogicalOperatorToString(op->type));
		// Every source the plan actually scans: base tables by resolved identity, table functions by name. Views
		// are expanded by now (secure views retain their wrapper). The private bind's callback recorded who
		// reached each table: an identity the caller's binders retrieved or its text names is authorized again;
		// one only trusted definitions retrieved is theirs. The engine's plan may scan no source
		// the private bind did not, and none more often: a plan that does (a relation whose SQL rendering
		// diverged from its query node) is refused rather than authorized. A Prepare() pre-screen has no private
		// bind to compare against and defers.
		if (op->type == LogicalOperatorType::LOGICAL_GET && origin != PlanOrigin::PRESCREEN) {
			auto &get = op->Cast<LogicalGet>();
			auto table = get.GetTable();
			if (table) {
				auto catalog = engine::CatalogName(table->schema.catalog), name = engine::EntryName(*table);
				auto schema = engine::SchemaPath(table->schema);
				account(provenance.validated_scans, remaining, gatekeeper::ObjectKey(catalog, schema, name),
				        {gatekeeper::rules::STATEMENT,
				         "plan scans an object more often than the validated statement did", catalog, schema, name});
				AuthorizeObject(layers, unit.binding, *table, result,
				                provenance.ObjectAttributable(unit.binding, catalog, schema, name));
			} else {
				auto &scan = engine::FunctionName(get.function);
				account(provenance.validated_function_scans, remaining_functions, scan,
				        {gatekeeper::rules::STATEMENT,
				         "plan scans a source more often than the validated statement did",
				         "",
				         {},
				         "",
				         scan});
			}
		}
		for (auto &child : op->children)
			operators.push_back(child.get());
	}
	AuthorizePlan(layers, unit.binding, unit.provenance, plan, result);
}

// What one private bind checks against: the layers, the caller's text as the walk recorded it, the origin the
// bind learns as it goes, and the result it fills. Shared by every binder the bind creates (the catalog-lookup
// callback is copied into each) and read by the replacement gate while the bind runs. No context spans the
// text, bind and plan phases: they have different inputs, and only the bind writes provenance. (The engine's
// own duckdb::BindContext is the binder's table of bindings, hence the name.)
struct PrivateBind {
	const gatekeeper::Layers &layers;
	const gatekeeper::BindingPolicy &binding;
	gatekeeper::Provenance &provenance;
	gatekeeper::Result &result;
};

// Replacement scans run when a table name resolves to no catalog object. DuckDB's callbacks only
// construct a TableRef; the reader binds (and may open files) afterwards. Gatekeeper installs the
// first callback at LOAD and decides before that bind happens, both while Authorize is binding on
// this thread and on every enforced connection. The resolved reader is authorized as the caller-written
// table function it stands for when the caller wrote the name, and as a trusted definition's own reader,
// against the deny layer only, when the name is reachable only through a view or macro body.
struct ValidationScope {
	ClientContext &context;       // the connection this validation binds on
	const PrivateBind &bind;      // what it checks against
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
                                                      optional_ptr<ReplacementScanData>);

// What the host's callbacks made of a name the catalog did not have. Not a pure lookup: each callback receives the
// connection, can throw, and can re-enter validation on another connection (the ScopeGuard in AuthorizeStatement
// restores this bind's scope afterwards). The callbacks are asked in the engine's order, after Gatekeeper's own,
// and the first to answer ends the loop, so each runs at most once per lookup here.
struct Resolution {
	enum class Kind {
		UNCLAIMED,  // no callback claimed the name
		FUNCTION,   // a callback produced the table function `name`; `ref` is what it produced
		UNSUPPORTED // a callback produced something no policy can authorize; `reason` says what
	};
	Kind kind = Kind::UNCLAIMED;
	unique_ptr<TableRef> ref;
	string name, reason;
};

static Resolution ResolveHostReplacement(ClientContext &context, ReplacementScanInput &input) {
	// The name as asked, taken before any callback runs. (input's names are const references, so a callback
	// cannot change them; this keeps the message independent of that guarantee.)
	auto path = engine::ReplacementPath(input);
	auto &config = DBConfig::GetConfig(context);
	for (auto &scan : config.replacement_scans) {
		if (scan.function == GatekeeperReplacementScan)
			continue;
		// Callbacks construct a TableRef without binding it; nothing is opened here.
		auto replacement = scan.function(context, input, scan.data.get());
		if (!replacement)
			continue;
		if (replacement->type != TableReferenceType::TABLE_FUNCTION)
			return {Resolution::Kind::UNSUPPORTED, std::move(replacement), "",
			        "host-language replacement scan cannot be authorized: " + path};
		auto &function = replacement->Cast<TableFunctionRef>().function;
		if (!function || function->GetExpressionClass() != ExpressionClass::FUNCTION)
			return {Resolution::Kind::UNSUPPORTED, std::move(replacement), "",
			        "replacement scan has no resolvable function: " + path};
		auto name = engine::FunctionName(function->Cast<FunctionExpression>());
		return {Resolution::Kind::FUNCTION, std::move(replacement), std::move(name), ""};
	}
	return {};
}

static unique_ptr<TableRef> GatekeeperReplacementScan(ClientContext &context, ReplacementScanInput &input,
                                                      optional_ptr<ReplacementScanData>) {
	auto scope = active_scope;
	if (scope && &context != &scope->context)
		scope = nullptr; // A reentrant connection on this thread is not the one being validated.
	auto gate = scope ? GateMode::ENFORCE : ReplacementGate(context);
	if (gate == GateMode::OPEN)
		return nullptr; // Ordinary connections, and log-only statements already decided, bind as the engine would.
	auto path = engine::ReplacementPath(input);
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
		binding = &scope->bind.binding;
	} else {
		enforced = AdmittedPolicy(context);
		binding = AdmittedBinding(context);
		if (!enforced) {
			gatekeeper::Result result;
			if (TryGlobalPolicy(context, prepared, result))
				enforced = &prepared;
			else if (record(result, nullptr))
				return nullptr;
		}
	}
	// A name the caller wrote chooses the reader, so the reader must be allowed like a caller-written table
	// function. A name reachable only through a trusted view or macro body is that definition's reader and is
	// outside function policy, exactly as the readers such bodies name explicitly are. The callback cannot see
	// which binder asked: a name the caller also wrote is the caller's, query-wide.
	bool caller_written = !binding || binding->caller_table_names.count(engine::ReplacementName(input));
	// Returns true when the engine should go on to bind the replacement as produced (log-only); refuses otherwise.
	auto deny = [&](const string &rule, const string &message, const string &function = "") {
		if (!scope) {
			gatekeeper::Result result;
			result.violations.emplace(rule, message, "", gatekeeper::NamePath{}, path, function);
			MarkDenied(result);
			return record(result, enforced);
		}
		scope->bind.result.violations.emplace(rule, message, "", gatekeeper::NamePath{}, path, function);
		throw PermissionException("replacement scan is not allowed");
	};
	auto resolution = ResolveHostReplacement(context, input);
	switch (resolution.kind) {
	case Resolution::Kind::UNSUPPORTED:
		if (deny(gatekeeper::rules::REPLACEMENT_SCAN, resolution.reason))
			return std::move(resolution.ref);
		throw InternalException("Gatekeeper refused replacement returned");
	case Resolution::Kind::FUNCTION: {
		// The layers the reader is held to: under Authorize both, on an enforced connection the snapshot alone.
		vector<const gatekeeper::Policy *> layers;
		if (scope)
			layers = {&scope->bind.layers.ceiling, &scope->bind.layers.policy};
		else
			layers = {enforced.get()};
		auto canonical = gatekeeper::CanonicalFunction(resolution.name);
		for (const auto *layer : layers) {
			if (caller_written && !gatekeeper::FunctionAllowed(*layer, resolution.name)) {
				if (deny(gatekeeper::rules::FUNCTION, "replacement scan function is not allowed: " + canonical,
				         canonical))
					return std::move(resolution.ref);
			}
		}
		if (scope) {
			scope->authorized.insert(gatekeeper::Lower(input.table_name));
			scope->bind.result.objects.insert({"", {}, path, "replacement"});
		}
		return std::move(resolution.ref);
	}
	case Resolution::Kind::UNCLAIMED:
		break;
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
	engine::MissingReplacement(context, input);
	throw BinderException("Table \"%s\" appeared during binding; retry the statement", path);
}

void InstallReplacementScan(DBConfig &config) {
	for (auto &scan : config.replacement_scans)
		if (scan.function == GatekeeperReplacementScan)
			return;
	config.replacement_scans.insert(config.replacement_scans.begin(), ReplacementScan(GatekeeperReplacementScan));
}

// The function names a scalar macro's definition introduces, read the way the binding boundary reads the
// caller's text: each overload's expression and default arguments are serialized as the select list of an
// empty SELECT and walked by the same grammar walker, so syntax-implied names (list_value for [..],
// struct_extract for x.y) are learned the same way. The walk's verdict is irrelevant here and discarded; only
// the names it records are kept. The table references the definition writes (in its subqueries) are learned
// by the same walk, for the same reason: the body binds in the caller's binder, so the objects it reads can
// only be recognized by name.
static void MacroBodyNames(ScalarMacroCatalogEntry &macro, gatekeeper::Names &names,
                           gatekeeper::WrittenNames *tables = nullptr) {
	auto node = make_uniq<SelectNode>();
	for (auto &overload : macro.macros) {
		node->select_list.push_back(overload->Cast<ScalarMacroFunction>().expression->Copy());
		for (auto &parameter : overload->default_parameters)
			node->select_list.push_back(parameter.second->Copy());
	}
	node->from_table = make_uniq<EmptyTableRef>();
	SelectStatement select;
	select.node = std::move(node);
	auto ast = SerializeStatement(select);
	gatekeeper::BindingPolicy body;
	gatekeeper::Validate(yyjson_doc_get_root(ast.get()), gatekeeper::Policy(), &body);
	for (const auto *set : {&body.caller_functions, &body.synthesized_functions, &body.literal_constructors})
		names.insert(set->begin(), set->end());
	if (tables)
		tables->insert(body.caller_table_names.begin(), body.caller_table_names.end());
	// A COLLATE in the body binds its collation's function (lower, icu_collate_de, ...) directly, never through
	// the catalog callback, so there is no lookup to recognize here: the plan walk attributes a collation
	// function to the caller only when the caller wrote COLLATE (BindingPolicy::caller_collates).
}

// The catalog-lookup callback of one binder. The binder gives no other signal of scope, so the callback carries
// it: DuckDB copies a binder's callback into every child binder it creates (CatalogEntryRetriever::Inherit),
// and creates the binder for a view or table macro body right after retrieving that entry. Retrieving a host
// view or table macro arms the copy that made the lookup; the next copy made from it, the body's binder, starts
// trusted, and trusted copies beget trusted copies. Lookups a trusted copy makes are that definition's own:
// outside table policy, the allowlists, blocks and the never-bind list alike, recorded as evidence, and
// attributed to nothing, with one exception: Gatekeeper's control plane is refused on every route. A scalar
// macro body binds in the caller's own binder, so its names and table references are learned from its
// definition instead, and an object the caller's text names is the caller's wherever it binds.
struct LookupCallback {
	shared_ptr<PrivateBind> bind;
	bool trusted = false;
	mutable bool armed = false;
	explicit LookupCallback(shared_ptr<PrivateBind> bind_p) : bind(std::move(bind_p)) {}
	LookupCallback(const LookupCallback &other) : bind(other.bind), trusted(other.trusted || other.armed) {
		other.armed = false;
	}
	LookupCallback &operator=(const LookupCallback &) = delete;
	void operator()(CatalogEntry &entry) {
		auto &s = *bind;
		bool function = FunctionKind(entry.type) != nullptr;
		if (!function) {
			if (entry.type != CatalogType::TABLE_ENTRY && entry.type != CatalogType::VIEW_ENTRY)
				return;
			// An object the caller names is the caller's, whichever binder retrieved it. Otherwise it is the
			// caller's when the caller's own binder retrieved it and no host scalar-macro body names it.
			auto &object = entry.Cast<StandardEntry>();
			auto catalog = engine::CatalogName(object.schema.catalog);
			auto schema = engine::SchemaPath(object.schema);
			auto &name = engine::EntryName(entry);
			bool attributable =
			    s.provenance.CallerNamesObject(s.binding, catalog, schema, name) ||
			    (!trusted && !gatekeeper::NamesObject(s.provenance.trusted_table_names, catalog, schema, name));
			(attributable ? s.provenance.caller_objects : s.provenance.trusted_objects)
			    .insert(gatekeeper::ObjectKey(catalog, schema, name));
			AuthorizeObject(s.layers, s.binding, entry, s.result, attributable);
			// A host view's body is trusted, and so is the body of any view a trusted definition reached: an
			// internal metadata view a host scalar-macro body names is the macro's, readers included. The same
			// internal view the caller names keeps its readers on the caller's never-bind list. Secure views use
			// the same VIEW_ENTRY lookup and child binder; the engine wraps the plan only after binding the body.
			if (!trusted && entry.type == CatalogType::VIEW_ENTRY && (!entry.internal || !attributable))
				armed = true;
			return;
		}
		auto canonical = gatekeeper::CanonicalFunction(engine::EntryName(entry));
		// A name a host scalar-macro body introduced is the body's, unless the caller can produce it too, in its
		// text or through a default macro its text expands to: then it is the caller's, query-wide, since both
		// bind in the same binder.
		bool attributable = !trusted && !(s.provenance.trusted_names.count(canonical) &&
		                                  !s.provenance.CallerCanName(s.binding, canonical));
		AuthorizeObject(s.layers, s.binding, entry, s.result, attributable);
		if (attributable)
			s.provenance.caller_lookups.insert(canonical);
		if (trusted)
			return;
		// A host table macro's body binds in the next child binder. So does what a table function a trusted
		// definition named binds in turn: query_table(n) in a host scalar-macro body replaces itself with a
		// subquery over the table it selects, and that subquery is the macro's, whatever table it names. The
		// caller's own query_table is never-bind before this point.
		if ((entry.type == CatalogType::TABLE_MACRO_ENTRY && (!entry.internal || !attributable)) ||
		    (entry.type == CatalogType::TABLE_FUNCTION_ENTRY && !attributable))
			armed = true;
		if (entry.type != CatalogType::MACRO_ENTRY)
			return;
		auto &macro = entry.Cast<ScalarMacroCatalogEntry>();
		// A host scalar macro's body, and the default macros such a body expands to, are trusted names, and the
		// objects its subqueries read are trusted objects. A default macro the caller reached is the caller's,
		// and so is everything its body names.
		if (!entry.internal || !attributable)
			MacroBodyNames(macro, s.provenance.trusted_names, &s.provenance.trusted_table_names);
		else
			MacroBodyNames(macro, s.provenance.caller_expansions);
	}
};

// Binds statement, the unit's own or a copy of it, against the unit's text record; fills the unit's provenance.
static void AuthorizeStatement(ClientContext &context, const gatekeeper::Layers &layers, SQLStatement &statement,
                               TextCheck::Unit &unit, optional_ptr<const engine::ParameterMap> parameters,
                               gatekeeper::Result &result) {
	engine::ParameterMap parameter_data;
	if (parameters)
		parameter_data = *parameters;
	BoundParameterMap bound_parameters(parameter_data);
	auto binder = Binder::CreateBinder(context);
	binder->SetParameters(bound_parameters);
	binder->SetBindingMode(BindingMode::EXTRACT_REPLACEMENT_SCANS);
	auto bind = make_shared_ptr<PrivateBind>(PrivateBind{layers, unit.binding, unit.provenance, result});
	binder->SetCatalogLookupCallback(LookupCallback(bind));
	ValidationScope scope{context, *bind, {}};
	BoundStatement bound;
	{
		ScopeGuard guard(scope);
		bound = binder->Bind(statement);
	}
	// Unlike Planner::CreatePlan, never turn ParameterNotResolved into a partial success.
	// parameters.rebind is a cache hint, not incomplete binding.
	if (!bound.plan)
		throw BinderException(gatekeeper::PARAMETERS_REQUIRED);
	// Some bind callbacks return placeholder plans instead of throwing ParameterNotResolved.
	// Mirror Planner's bound_all_parameters type check: execution must not choose a different
	// implementation after validation by resolving an UNKNOWN parameter for the first time.
	for (const auto &entry : bound_parameters.GetParameters())
		if (!entry.second->return_type.IsValid())
			throw BinderException(gatekeeper::PARAMETERS_REQUIRED);
	CheckPlan(layers, unit, PlanOrigin::PRIVATE, binder->GetStatementProperties(), *bound.plan, result);
	// Backstop: every replacement DuckDB recorded must have passed the Gatekeeper callback.
	for (auto &entry : binder->GetReplacementScans()) {
		auto &path = engine::Str(entry.first);
		if (!scope.authorized.count(gatekeeper::Lower(path)))
			result.violations.emplace(gatekeeper::rules::REPLACEMENT_SCAN,
			                          "replacement scan was not authorized: " + path, "", gatekeeper::NamePath{}, path);
	}
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
		auto &entry = engine::GetEntry(context, CatalogType::TYPE_ENTRY, INVALID_CATALOG, INVALID_SCHEMA, name);
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
			distinct |=
			    SubstitutePivotEnums(context, *engine::Subquery(expr.Cast<SubqueryExpression>()).node, enums, large);
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
			    auto &pivot_enum = engine::Str(column.pivot_enum);
			    if (!pivot_enum.empty() && enums.count(pivot_enum))
				    dynamic.emplace_back(column);
			    else if (!column.entries.empty())
				    multiply(column.entries.size());
			    else if (!pivot_enum.empty())
				    multiply(HostEnumSize(context, pivot_enum));
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
			    column.get().pivot_enum = engine::Name();
			    for (idx_t i = 0; i < count; i++) {
				    PivotColumnEntry entry;
				    auto alias = std::to_string(i);
				    entry.alias = engine::ToName(alias);
				    for (size_t n = 0; n < column.get().pivot_expressions.size(); n++)
					    entry.values.emplace_back(alias);
				    column.get().entries.push_back(std::move(entry));
			    }
			    count = 1;
		    }
	    });
	return distinct;
}

void Authorize(ClientContext &context, const gatekeeper::Layers &layers, TextCheck::Unit &unit,
               optional_ptr<const engine::ParameterMap> parameters, gatekeeper::Result &result) {
	if (unit.pivot_enums.empty()) {
		if (unit.statement->type == StatementType::SELECT_STATEMENT)
			return AuthorizeStatement(context, layers, *unit.statement, unit, parameters, result);
		// Binder::Bind moves a CreateStatement's definition into the plan; keep the admitted statement intact.
		auto copy = unit.statement->Copy();
		return AuthorizeStatement(context, layers, *copy, unit, parameters, result);
	}
	for (bool large : {false, true}) {
		auto copy = unit.statement->Copy();
		if (!SubstitutePivotEnums(context, PivotQuery(*copy), unit.pivot_enums, large) && large)
			break;
		AuthorizeStatement(context, layers, *copy, unit, parameters, result);
	}
}

bool DescribeError(const ErrorData &data, bool binding, gatekeeper::Result &result) {
	switch (data.Type()) {
	case ExceptionType::PARSER: {
		result.code = gatekeeper::codes::PARSER;
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
		result.code = gatekeeper::EngineErrorCode(binding);
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
		result.error_message = gatekeeper::PARAMETERS_REQUIRED;
	return true;
}

bool DescribeError(const std::exception &error, bool binding, gatekeeper::Result &result) {
	if (auto invalid = dynamic_cast<const std::invalid_argument *>(&error)) {
		result.code = gatekeeper::EngineErrorCode(binding);
		result.error_message = invalid->what();
		return true;
	}
	if (dynamic_cast<const std::bad_alloc *>(&error))
		return false;
	return DescribeError(ErrorData(error), binding, result);
}

gatekeeper::Result Check(ClientContext &context, const gatekeeper::Layers &layers, const string &sql,
                         const gatekeeper::Limits &limits) {
	gatekeeper::Result result;
	bool binding = false;
	try {
		auto text = CheckText(context, layers, sql, limits);
		binding = true;
		// The engine runs a batch in order and stops at the first statement that fails, so the statements
		// admitted before a denied one bind first: a bind that fails among them is the decision, as it would
		// be the engine's error, and only if they all pass is the later text denial reported.
		for (auto &unit : text.units)
			Authorize(context, layers, unit, nullptr, result);
		if (!text.result.allowed)
			return text.result;
		result.allowed = true;
		result.code = gatekeeper::codes::OK;
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
		result.code = gatekeeper::codes::FORBIDDEN;
		result.error_type.clear();
		result.error_message.clear();
	}
}

string DenialMessage(const gatekeeper::Result &result) {
	string message = "Gatekeeper denied this statement";
	if (!result.code.empty() && result.code != gatekeeper::codes::FORBIDDEN)
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
