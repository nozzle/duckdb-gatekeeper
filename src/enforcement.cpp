#include "enforcement.hpp"
#include "audit.hpp"
#include "check.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/prepared_statement_data.hpp"
#include "duckdb/main/settings.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/planner_extension.hpp"
#include "engine_api.hpp"
#include "policy_setting.hpp"
#include "remote_scope.hpp"
#include "single_row.hpp"

namespace duckdb {

// The registered_state key of the enforced state; a C++-side name, never a setting.
static constexpr const char *STATE_KEY = "gatekeeper_enforced";
static constexpr const char *LOG_ONLY_SETTING = "gatekeeper_log_only";

// The global log-only switch as it stands now. Only a readable true suspends refusals: a value written natively
// without passing the SET callback fails closed, toward enforcing.
static bool LogOnlySetting(ClientContext &context) {
	Value value;
	if (!DBConfig::GetConfig(context).TryGetCurrentSetting(LOG_ONLY_SETTING, value))
		return false;
	return !value.IsNull() && value.type().id() == LogicalTypeId::BOOLEAN && BooleanValue::Get(value);
}

static DecisionMode ModeFor(bool log_only) { return log_only ? DecisionMode::LOG_ONLY : DecisionMode::ENFORCE; }

// The per-connection latch. Its presence in ClientContext::registered_state is what makes a connection
// enforced; nothing removes it. A connection is enforced only because the host ran gatekeeper_enforce() on
// it: there is no instance-wide switch, so nothing depends on when a connection was opened, and the host's
// own connections stay free to read the audit log and change the policy. Within one query the state
// carries the decision between the engine hooks.
//
// Two entry points reach execution. Query(): QueryBegin sees the statement text, admits it, and binds it
// privately with catalog authorization when it has no parameters; the engine then binds and PostBind
// re-checks that plan. Prepare() then Execute(): Prepare only pre-screens the plan's structure, since its
// parameter values are not known; at execution QueryBegin admits the text, the rebind hook forces a rebind
// inside the query, and PostBind authorizes and re-checks the plan that will execute. Parameter values
// are known only to the engine's binder, so parameterized statements are authorized in PostBind.
//
// Where those two run differs by engine. DuckDB 1.5 binds Prepare() before any hook and outside any
// statement, and asks OnExecutePrepared before running the prepared plan. DuckDB 2.0 runs both as internal
// statements carrying the prepared text (ClientContext::PrepareInternal, PreparedStatement::Execute): a
// PREPARE whose nested plan is bound in BindingMode::PREPARE, and an EXECUTE that asks
// OnRebindPreparedStatement before rebinding. Each reaches PostBind twice, the statement's own plan first and
// the wrapper (LOGICAL_PREPARE, LOGICAL_EXECUTE) after; the wrapper runs nothing of its own and is accepted
// exactly when its plan was decided under this statement. The text boundary admits that text as the SELECT it
// is; a caller's own PREPARE or EXECUTE is refused there as an unsupported statement.
//
// One result accumulates across the boundaries and is recorded exactly once per statement: at the boundary
// that denies it, or as allowed once the plan the engine will execute has passed.
//
// gatekeeper_log_only is read once per statement next to the policy. In log-only mode the same checks run in
// the same places and write the same record, and a denial refuses nothing: the engine goes on to bind and
// execute the statement as it would on an unenforced connection. The record already stands, so the hooks the
// engine then reaches for that statement do not decide it again.
//
// The flags are four separate dimensions, not one phase, and hold these invariants between the hooks:
//   - authorized ⇒ admitted ⇒ in_statement: each is set only by the step after the one before it, and Reset
//     clears all of them together at QueryBegin and QueryEnd. policy, log_only and unit are meaningful only
//     while in_statement; unit.statement is set only while admitted.
//   - decided is orthogonal to admission: a statement is decided at whichever boundary first writes its
//     record, admitted or not, and never twice. Only log-only mode reads it: enforcing, a denial throws out
//     of the hook that recorded it and the engine ends the query.
//   - prepare_decided is meaningful only outside a statement (!in_statement): it marks a Prepare() bind the
//     replacement gate already recorded, is consumed by the pre-screen or cleared when the prepare attempt
//     ends (OnFinalizePrepare, OnPlanningError), and is never set inside a statement.
//   - executing_prepared and prescreened (DuckDB 2.0) are set inside a statement only: the first by the rebind
//     hook, marking the nested plan that follows as the one that will execute; the second by the pre-screen
//     of a Prepare()'s nested plan, which its PREPARE wrapper then consumes.
struct EnforcementState : ClientContextState {
	gatekeeper::Policy policy;       // one snapshot for the whole statement
	gatekeeper::Result result;       // the decision in progress
	bool log_only = false;           // this statement is recorded and never refused
	bool in_statement = false;       // QueryBegin has run: the snapshots describe the statement in progress
	bool decided = false;            // the statement's record has been written
	bool prepare_decided = false;    // a Prepare() outside any statement was decided at the replacement gate
	bool admitted = false;           // text passed the binding boundary
	bool authorized = false;         // private bind with catalog authorization passed
	bool executing_prepared = false; // 2.0: this statement is an EXECUTE whose rebind the hook forced
	bool prescreened = false;        // 2.0: this statement is a PREPARE whose nested plan passed the pre-screen
	TextCheck::Unit unit;            // the admitted statement, awaiting parameter values when it has any

	// An enforced connection has no request layer: the statement's snapshot stands in both positions, and every
	// check runs as gatekeeper_validate runs it with no options.
	gatekeeper::Layers Snapshot() const { return {policy, policy}; }
	void Reset() {
		policy = gatekeeper::Policy();
		result = gatekeeper::Result();
		log_only = false;
		in_statement = false;
		decided = false;
		prepare_decided = false;
		admitted = false;
		authorized = false;
		executing_prepared = false;
		prescreened = false;
		unit = TextCheck::Unit();
	}
	// The statement's record, and in ENFORCE mode its refusal. Marked before Decide can throw.
	void Record(ClientContext &context, Boundary boundary, optional_ptr<const gatekeeper::Policy> in_force,
	            optional_ptr<const string> sql) {
		decided = true;
		Decide(context, {ModeFor(log_only), boundary, in_force, sql}, result);
	}
	// Runs the same private authorization gatekeeper_validate performs. An engine error while binding privately
	// (a missing table, a type error) is not a decision. Enforcing, it propagates unchanged: DuckDB's own message
	// is the outcome. Log-only, nothing from the private path may surface: the statement is recorded as
	// gatekeeper_validate would report it, and the engine's own bind raises the error, carrying the query
	// location a hook cannot attach, or runs the statement if it binds after all.
	void Authorize(ClientContext &context, optional_ptr<const engine::ParameterMap> parameters) {
		try {
			duckdb::Authorize(context, Snapshot(), unit, parameters, result);
		} catch (const PermissionException &) {
			MarkDenied(result);
			Record(context, Boundary::AUTHORIZE, &policy, &context.GetCurrentQuery());
			return;
		} catch (const std::exception &error) {
			if (!log_only || !DescribeError(error, true, result))
				throw;
			MarkDenied(result);
			Record(context, Boundary::AUTHORIZE, &policy, &context.GetCurrentQuery());
			return;
		}
		authorized = true;
	}
	void QueryBegin(ClientContext &context) override {
		// On DuckDB 2.0 this is AFTER SubmitStatement's connected-session RemoteExecute callback.
		// Safety on normal SQL routes comes from refusing CONNECT below (CheckText's non-SELECT
		// rejection) while still local, not from inspecting connected state here. Native hosts must
		// keep enforced connections local; see docs/security.md#connect-mode-and-native-host-state.
		Reset();
		in_statement = true;
		log_only = LogOnlySetting(context);
		const auto &sql = context.GetCurrentQuery();
		if (!TryGlobalPolicy(context, policy, result)) {
			Record(context, Boundary::BINDING, nullptr, &sql);
			return;
		}
		if (!CheckRemoteScope(context, result)) {
			MarkDenied(result);
			Record(context, Boundary::BINDING, &policy, &sql);
			return;
		}
		// The two errors the binding boundary raises for text it cannot read (see CheckText), described exactly
		// as gatekeeper_validate describes them, parser position included. Nothing wider is caught: any other
		// exception here is the engine's own and propagates.
		TextCheck text;
		try {
			text = CheckText(context, Snapshot(), sql, gatekeeper::Limits());
		} catch (const ParserException &error) {
			DescribeError(ErrorData(error), false, result);
			Record(context, Boundary::BINDING, &policy, &sql);
			return;
		} catch (const InvalidInputException &error) {
			DescribeError(ErrorData(error), false, result);
			Record(context, Boundary::BINDING, &policy, &sql);
			return;
		}
		result = std::move(text.result);
		if (!result.allowed) {
			Record(context, Boundary::BINDING, &policy, &sql);
			return;
		}
		// The engine presents one statement at a time here: a dynamic PIVOT arrives as the statements its
		// preprocessor rewrote it into, each with its own text, never as the batch. Fail closed on anything else.
		if (text.units.size() != 1 || !text.units[0].pivot_enums.empty()) {
			result = gatekeeper::UnsupportedStatement();
			Record(context, Boundary::BINDING, &policy, &sql);
			return;
		}
		admitted = true;
		unit = std::move(text.units[0]);
		if (!CheckParameters(context))
			return;
		if (unit.statement->named_param_map.empty())
			Authorize(context, nullptr);
	}
	bool CheckParameters(ClientContext &context) {
		try {
			// QueryBegin has only text; 2.0's rebind hook already receives values merged with variable defaults.
			// Neither hook can establish explicit-value precedence. Refuse collisions before the engine binds.
			CheckParameterFallbacks(context, Snapshot(), unit.binding, nullptr, false, result);
		} catch (const PermissionException &) {
			MarkDenied(result);
			Record(context, Boundary::BINDING, &policy, &context.GetCurrentQuery());
			return false;
		}
		return true;
	}
	void QueryEnd(ClientContext &context, optional_ptr<ErrorData> error) override {
		if (in_statement && log_only && !decided && error && error->HasError()) {
			// The engine failed the statement after QueryBegin admitted it and before any hook could decide it:
			// a parameter the caller did not supply, or one whose type never resolved, for which the planner
			// yields no plan and no planning error. Recorded as gatekeeper_validate reports the failure; the
			// engine has already closed the query, so the record carries no query id.
			if (DescribeError(*error, true, result)) {
				MarkDenied(result);
				Record(context, Boundary::AUTHORIZE, &policy, unit.statement ? &unit.statement->query : nullptr);
			}
		}
		Reset();
	}
	// The gate's Prepare() mark must not outlive the prepare attempt that set it: a bind that fails after the
	// gate decided it runs no pre-screen to consume the mark, and nothing else separates one Prepare() from the
	// next inside an explicit transaction. Declaring that this state can request a rebind makes the engine
	// report how every prepare attempt ended, OnFinalizePrepare or OnPlanningError, at the cost of binding a
	// copy of the statement; no rebind is ever requested from here.
	bool CanRequestRebind() override { return true; }
	RebindQueryInfo OnPlanningError(ClientContext &context, SQLStatement &, ErrorData &error) override {
		if (!in_statement) {
			prepare_decided = false;
		} else if (log_only && !decided) {
			// The engine's own bind failed before any hook could decide the statement: parameters deferred the
			// private bind to PostBind, which was never reached. Enforcing, the same failure is DuckDB's error
			// and no decision. Log-only, the trail must still show the statement, so it is recorded as
			// gatekeeper_validate reports the error, here rather than at QueryEnd so the record carries the
			// query's identity; the engine's exception then propagates unchanged.
			if (DescribeError(error, true, result)) {
				MarkDenied(result);
				Record(context, Boundary::AUTHORIZE, &policy, &context.GetCurrentQuery());
			}
		}
		return RebindQueryInfo::DO_NOT_REBIND;
	}
	RebindQueryInfo OnFinalizePrepare(ClientContext &, PreparedStatementData &, PreparedStatementMode) override {
		if (!in_statement)
			prepare_decided = false;
		return RebindQueryInfo::DO_NOT_REBIND;
	}
	// A prepared statement executed through the client API: its plan was built before this query began, so
	// rebinding inside the query means the plan that executes is the one PostBind authorizes under this
	// statement's policy snapshot. DuckDB 1.5 runs the prepared plan directly and asks here first; 2.0 runs an
	// internal EXECUTE statement carrying the prepared text (PreparedStatement::CreateExecuteStatement) and
	// asks while binding it, the same hook a caller's own EXECUTE reaches, which the text boundary has already
	// refused as an unsupported statement.
	RebindQueryInfo ForceRebind(ClientContext &context) {
		if (!admitted && !decided) {
			result = gatekeeper::NotAdmitted();
			Record(context, Boundary::BINDING, &policy, &context.GetCurrentQuery());
		}
		// A retained native handle gets the same conservative gate on every execution. Do not infer supplied
		// provenance from the callback's merged map. In log-only mode an earlier decision already stands.
		if (admitted && !decided)
			CheckParameters(context);
		executing_prepared = true;
		return RebindQueryInfo::ATTEMPT_TO_REBIND;
	}
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	RebindQueryInfo OnRebindPreparedStatement(ClientContext &context, BindPreparedStatementCallbackInfo &,
	                                          RebindQueryInfo) override {
		return ForceRebind(context);
	}
#else
	RebindQueryInfo OnExecutePrepared(ClientContext &context, PreparedStatementCallbackInfo &,
	                                  RebindQueryInfo) override {
		return ForceRebind(context);
	}
#endif
};

static shared_ptr<EnforcementState> StateOf(ClientContext &context) {
	return context.registered_state->Get<EnforcementState>(STATE_KEY);
}

static void Latch(ClientContext &context) { context.registered_state->GetOrCreate<EnforcementState>(STATE_KEY); }

GateMode ReplacementGate(ClientContext &context) {
	auto state = StateOf(context);
	if (!state)
		return GateMode::OPEN;
	// Inside a statement the snapshot QueryBegin took governs every check of it; a Prepare() bind outside any
	// statement reads the setting as it stands.
	if (state->in_statement) {
		if (!state->log_only)
			return GateMode::ENFORCE;
		return state->decided ? GateMode::OPEN : GateMode::LOG_ONLY;
	}
	if (!LogOnlySetting(context))
		return GateMode::ENFORCE;
	return state->prepare_decided ? GateMode::OPEN : GateMode::LOG_ONLY;
}

void MarkGateDecided(ClientContext &context) {
	auto state = StateOf(context);
	if (!state)
		return;
	if (state->in_statement)
		state->decided = true;
	else
		state->prepare_decided = true;
}

optional_ptr<const string> AdmittedQuery(ClientContext &context) {
	auto state = StateOf(context);
	if (!state || !state->admitted)
		return nullptr;
	return &context.GetCurrentQuery();
}

optional_ptr<const gatekeeper::Policy> AdmittedPolicy(ClientContext &context) {
	auto state = StateOf(context);
	if (!state || !state->admitted)
		return nullptr;
	return &state->policy;
}

optional_ptr<const gatekeeper::BindingPolicy> AdmittedBinding(ClientContext &context) {
	auto state = StateOf(context);
	if (!state || !state->admitted)
		return nullptr;
	return &state->unit.binding;
}

// Execution boundary on every plan the engine's own planner produces, for every connection.
static void PostBind(PlannerExtensionInput &input, BoundStatement &statement) {
	auto state = StateOf(input.context);
	if (!state || !statement.plan)
		return;
	auto &context = input.context;
	if (!state->in_statement) {
		// DuckDB 1.5's Prepare(): no query is active and the text has not been seen. This plan cannot execute
		// before OnExecutePrepared forces a rebind inside a query, so only pre-screen it here.
		if (state->prepare_decided) {
			// The replacement gate already recorded this bind's denial (log-only) and let it continue.
			state->prepare_decided = false;
			return;
		}
		auto mode = ModeFor(LogOnlySetting(context));
		gatekeeper::Policy policy;
		gatekeeper::Result result;
		if (!TryGlobalPolicy(context, policy, result)) {
			Decide(context, {mode, Boundary::PREPARE, nullptr, nullptr}, result);
			return;
		}
		result.allowed = true;
		try {
			// Plan structure only: with no text and no private bind, nothing here can be attributed, so table
			// policy and blocks wait for the rebind inside the query, as gatekeeper::Provenance::unattributed says.
			auto unattributed = TextCheck::Unit::Unattributed();
			CheckPlan({policy, policy}, unattributed, PlanOrigin::PRESCREEN, input.binder.GetStatementProperties(),
			          *statement.plan, result);
		} catch (const PermissionException &) {
			MarkDenied(result);
			Decide(context, {mode, Boundary::PREPARE, &policy, nullptr}, result);
		}
		return;
	}
	if (state->log_only && state->decided) {
		// Decided at an earlier boundary and not refused: the engine is binding the statement anyway. The
		// record stands; nothing is decided twice.
		return;
	}
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	// DuckDB 2.0's Prepare() and Execute() statements (see the top of this file). The text boundary admitted
	// the prepared text; a caller's own PREPARE or EXECUTE never reaches here enforcing.
	if (input.binder.GetBindingMode() == BindingMode::PREPARE && !state->executing_prepared) {
		// The statement a Prepare() prepares. The binding mode alone does not identify it: an EXECUTE's rebind
		// also plans through Planner::PrepareSQLStatement, in PREPARE mode (bind_execute.cpp), so it is the flag
		// the rebind hook set beforehand that keeps the plan that will execute out of this branch. Parameter
		// values are not known yet here, so as under 1.5 only the plan's structure is decided; each execution is
		// authorized with its values when it rebinds.
		if (!state->admitted) {
			state->result = gatekeeper::NotAdmitted();
			state->Record(context, Boundary::PREPARE, &state->policy, &context.GetCurrentQuery());
			return;
		}
		try {
			auto unattributed = TextCheck::Unit::Unattributed();
			CheckPlan(state->Snapshot(), unattributed, PlanOrigin::PRESCREEN, input.binder.GetStatementProperties(),
			          *statement.plan, state->result);
		} catch (const PermissionException &) {
			MarkDenied(state->result);
			state->Record(context, Boundary::PREPARE, &state->policy, &context.GetCurrentQuery());
			return;
		}
		state->prescreened = true;
		return;
	}
	if (statement.plan->type == LogicalOperatorType::LOGICAL_PREPARE ||
	    statement.plan->type == LogicalOperatorType::LOGICAL_EXECUTE) {
		// The wrapper, planned after the statement it wraps reached this hook: a PREPARE whose plan passed
		// the pre-screen, or an EXECUTE whose rebound plan was authorized and recorded under this statement's
		// snapshot. Either runs nothing of its own and is accepted exactly when that decision exists; a wrapper
		// with none behind it would run a plan this statement never saw, and is refused.
		bool prepare = statement.plan->type == LogicalOperatorType::LOGICAL_PREPARE;
		if (prepare ? state->prescreened : (state->decided && state->result.allowed))
			return;
		state->result = gatekeeper::NotAdmitted();
		state->Record(context, prepare ? Boundary::PREPARE : Boundary::EXECUTION, &state->policy,
		              &context.GetCurrentQuery());
		return;
	}
#endif
	if (!state->admitted) {
		// In ENFORCE mode the binding-boundary denial refused the statement before the engine could plan it;
		// should a plan arrive regardless, fail closed rather than authorize what was never admitted.
		state->result = gatekeeper::NotAdmitted();
		state->Record(context, Boundary::EXECUTION, &state->policy, &context.GetCurrentQuery());
		return;
	}
	if (!state->authorized) {
		// The engine's binder holds the values this statement's parameters were bound with (it binds them as
		// constants); authorize the admitted statement privately with exactly those values.
		engine::ParameterMap values;
		if (auto parameters = input.binder.GetParameters())
			values = parameters->GetParameterData();
		state->Authorize(context, &values);
		if (!state->authorized)
			return;
	}
	try {
		CheckPlan(state->Snapshot(), state->unit, PlanOrigin::ENGINE, input.binder.GetStatementProperties(),
		          *statement.plan, state->result);
	} catch (const PermissionException &) {
		MarkDenied(state->result);
	}
	// The one record an allowed statement produces: the plan the engine will execute has passed.
	state->Record(context, Boundary::EXECUTION, &state->policy, &context.GetCurrentQuery());
}

static void SetLogOnly(ClientContext &context, SetScope scope, Value &value) {
	if (scope == SetScope::SESSION || scope == SetScope::LOCAL)
		throw InvalidInputException("gatekeeper_log_only is global-only");
	if (value.IsNull())
		throw InvalidInputException("gatekeeper_log_only must be true or false");
	// Record first: a log sink that refuses the entry fails this statement with nothing changed. The engine
	// stores the value after this returns; every enforced connection reads it at its next statement.
	LogSettingChange(context, "log_only_changed", value);
}

// Host settings Gatekeeper documents but deliberately never changes. Reported, not enforced.
static vector<string> PostureWarnings(ClientContext &context) {
	auto &config = DBConfig::GetConfig(context);
	vector<string> warnings;
	if (LogOnlySetting(context))
		warnings.push_back("gatekeeper_log_only is true: this connection records decisions and refuses nothing");
	if (Settings::Get<EnableExternalAccessSetting>(config))
		warnings.push_back("enable_external_access is true: readers reached through trusted views or macros can "
		                   "open files and URLs while binding");
	if (Settings::Get<AutoloadKnownExtensionsSetting>(config) ||
	    Settings::Get<AutoinstallKnownExtensionsSetting>(config))
		warnings.push_back("autoload_known_extensions or autoinstall_known_extensions is true: binding can load "
		                   "extensions on demand");
	if (!Settings::Get<LockConfigurationSetting>(config))
		warnings.push_back("lock_configuration is false: unenforced connections can still change gatekeeper_policy "
		                   "and gatekeeper_log_only");
	if (!DenialsRecorded(context))
		warnings.push_back("logging does not record Gatekeeper decisions: denials on this connection leave no "
		                   "audit record; CALL enable_logging('Gatekeeper')");
	return warnings;
}

struct EnforceBinding : FunctionData {
	unique_ptr<FunctionData> Copy() const override { return make_uniq<EnforceBinding>(); }
	bool Equals(const FunctionData &) const override { return true; }
};

static unique_ptr<FunctionData> BindEnforce(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &types,
                                            engine::NameList &names) {
	engine::RunAtOnce(input);
	types = {LogicalType::BOOLEAN, LogicalType::LIST(LogicalType::VARCHAR)};
	names = {"enforced", "warnings"};
	return make_uniq<EnforceBinding>();
}

static void Enforce(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<SingleRowState>();
	if (state.finished)
		return;
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	// IsConnected remains true when the weak target has expired: checking only the live catalog
	// would admit stale routing state. This protects the local activation body only. SQL submitted
	// on an already-connected session may have reached RemoteExecute before this body (or may
	// never reach it at all); the host must establish LOCAL state before submitting activation.
	if (context.IsConnected())
		throw PermissionException("gatekeeper_enforce() cannot run on a CONNECT-ed connection: DISCONNECT "
		                          "during trusted setup before activating local enforcement");
#endif
	// An enforced connection cannot end a transaction (COMMIT and ROLLBACK are not read statements), so latching
	// inside one the host opened would leave the connection in a transaction nothing can close. Refuse before
	// latching, with a Permission Error, which the engine's default transaction-invalidation policy lets the
	// transaction survive on DuckDB 1.5 (2.0 aborts it); either way the host ends the transaction first, or
	// enforces on a connection that has not begun one.
	if (!context.transaction.IsAutoCommit())
		throw PermissionException("gatekeeper_enforce() cannot run inside an open transaction: an enforced "
		                          "connection cannot COMMIT or ROLLBACK, so end the transaction first");
	// Latch at execution, never at bind: EXPLAIN and PREPARE must not enforce.
	SealRemoteScope(context);
	Latch(context);
	vector<Value> warnings;
	for (const auto &warning : PostureWarnings(context))
		warnings.emplace_back(warning);
	output.SetCardinality(1);
	output.SetValue(0, 0, Value::BOOLEAN(true));
	output.SetValue(1, 0, Value::LIST(LogicalType::VARCHAR, std::move(warnings)));
	state.finished = true;
}

void RegisterEnforcement(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	config.AddExtensionOption(LOG_ONLY_SETTING,
	                          "Whether enforced connections record every decision without refusing anything, "
	                          "instead of refusing what the policy denies",
	                          LogicalType::BOOLEAN, Value::BOOLEAN(false), SetLogOnly, SetScope::GLOBAL);
	PlannerExtension planner;
	planner.post_bind_function = PostBind;
	PlannerExtension::Register(config, planner);

	TableFunction enforce("gatekeeper_enforce", {}, Enforce, BindEnforce, InitSingleRow);
	FunctionDescription description;
	description.description = "Irreversibly makes this connection execute only statements the global Gatekeeper "
	                          "policy allows and reports host settings that weaken the sandbox.";
	description.examples = {"CALL gatekeeper_enforce()"};
	CreateTableFunctionInfo info(std::move(enforce));
	info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	info.descriptions.push_back(std::move(description));
	loader.RegisterFunction(std::move(info));
}
} // namespace duckdb
