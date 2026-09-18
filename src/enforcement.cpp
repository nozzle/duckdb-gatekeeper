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
#include "policy_setting.hpp"

namespace duckdb {

static constexpr const char *STATE_KEY = "gatekeeper_enforcement";
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

// Reads the global policy. An unreadable setting is decided as invalid_input: the fail-closed outcome for a
// sandbox whose policy was written without validation.
static bool ReadPolicy(ClientContext &context, gatekeeper::Policy &policy, gatekeeper::Result &result) {
	try {
		policy = GlobalPolicy(context);
		return true;
	} catch (const std::invalid_argument &error) {
		result = {false, "invalid_input", "", string("cannot read the global policy: ") + error.what()};
		return false;
	}
}

// The per-connection latch. Its presence in ClientContext::registered_state is what makes a connection
// enforced; nothing removes it. A connection is enforced only because the host ran gatekeeper_enforce() on
// it: there is no instance-wide switch, so nothing depends on when a connection was opened, and the host's
// own connections stay free to read the audit log and change the policy. Within one query the state
// carries the decision between the engine hooks.
//
// Two entry points reach execution. Query(): QueryBegin sees the statement text, admits it, and binds it
// privately with catalog authorization when it has no parameters; the engine then binds and PostBind
// re-checks that plan. Prepare() then Execute(): Prepare binds before any hook runs (PostBind only
// pre-screens that plan); at execution QueryBegin admits the text, OnExecutePrepared forces a rebind
// inside the query, and PostBind authorizes and re-checks the plan that will execute. Parameter values
// are known only to the engine's binder, so parameterized statements are authorized in PostBind.
//
// One result accumulates across the boundaries and is recorded exactly once per statement: at the boundary
// that denies it, or as allowed once the plan the engine will execute has passed.
//
// gatekeeper_log_only is read once per statement next to the policy. In log-only mode the same checks run in
// the same places and write the same record, and a denial refuses nothing: the engine goes on to bind and
// execute the statement as it would on an unenforced connection. The record already stands, so the hooks the
// engine then reaches for that statement do not decide it again.
struct EnforcementState : ClientContextState {
	gatekeeper::Policy policy;    // one snapshot for the whole statement
	gatekeeper::Result result;    // the decision in progress
	bool log_only = false;        // this statement is recorded and never refused
	bool in_statement = false;    // QueryBegin has run: the snapshots describe the statement in progress
	bool decided = false;         // the statement's record has been written
	bool prepare_decided = false; // a Prepare() outside any statement was decided at the replacement gate
	bool admitted = false;        // text passed the binding boundary
	bool authorized = false;      // private bind with catalog authorization passed
	gatekeeper::BindingPolicy binding;
	unique_ptr<SQLStatement> statement; // admitted statement awaiting parameter values

	void Reset() {
		policy = gatekeeper::Policy();
		result = gatekeeper::Result();
		log_only = false;
		in_statement = false;
		decided = false;
		prepare_decided = false;
		admitted = false;
		authorized = false;
		binding = gatekeeper::BindingPolicy();
		statement.reset();
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
	void Authorize(ClientContext &context, optional_ptr<const case_insensitive_map_t<BoundParameterData>> parameters) {
		try {
			duckdb::Authorize(context, policy, policy, *statement, binding, parameters, result);
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
		Reset();
		in_statement = true;
		log_only = LogOnlySetting(context);
		const auto &sql = context.GetCurrentQuery();
		if (!ReadPolicy(context, policy, result)) {
			Record(context, Boundary::BINDING, nullptr, &sql);
			return;
		}
		TextCheck text;
		try {
			text = CheckText(context, policy, policy, sql, gatekeeper::Limits());
		} catch (const ParserException &error) {
			result = {false, "parser", "parser", ErrorData(error).RawMessage()};
			Record(context, Boundary::BINDING, &policy, &sql);
			return;
		} catch (const InvalidInputException &error) {
			result = {false, "invalid_input", "", ErrorData(error).RawMessage()};
			Record(context, Boundary::BINDING, &policy, &sql);
			return;
		}
		result = std::move(text.result);
		if (!result.allowed) {
			Record(context, Boundary::BINDING, &policy, &sql);
			return;
		}
		admitted = true;
		binding = std::move(text.binding);
		statement = std::move(text.statements[0]); // MAX_STATEMENTS is 1
		if (statement->named_param_map.empty())
			Authorize(context, nullptr);
	}
	void QueryEnd(ClientContext &, optional_ptr<ErrorData>) override { Reset(); }
	// The gate's Prepare() mark must not outlive the prepare attempt that set it: a bind that fails after the
	// gate decided it runs no pre-screen to consume the mark, and nothing else separates one Prepare() from the
	// next inside an explicit transaction. Declaring that this state can request a rebind makes the engine
	// report how every prepare attempt ended, OnFinalizePrepare or OnPlanningError, at the cost of binding a
	// copy of the statement; no rebind is ever requested from here.
	bool CanRequestRebind() override { return true; }
	RebindQueryInfo OnPlanningError(ClientContext &, SQLStatement &, ErrorData &) override {
		if (!in_statement)
			prepare_decided = false;
		return RebindQueryInfo::DO_NOT_REBIND;
	}
	RebindQueryInfo OnFinalizePrepare(ClientContext &, PreparedStatementData &, PreparedStatementMode) override {
		if (!in_statement)
			prepare_decided = false;
		return RebindQueryInfo::DO_NOT_REBIND;
	}
	RebindQueryInfo OnExecutePrepared(ClientContext &context, PreparedStatementCallbackInfo &,
	                                  RebindQueryInfo) override {
		if (!admitted && !decided) {
			result = {false, "forbidden", "", "", {{"statement", "not admitted at the binding boundary"}}};
			Record(context, Boundary::BINDING, &policy, &context.GetCurrentQuery());
		}
		// The prepared plan was built before this query began. Rebinding inside the query means the plan
		// that executes is the one PostBind authorizes under this statement's policy snapshot.
		return RebindQueryInfo::ATTEMPT_TO_REBIND;
	}
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

// Execution boundary on every plan the engine's own planner produces, for every connection.
static void PostBind(PlannerExtensionInput &input, BoundStatement &statement) {
	auto state = StateOf(input.context);
	if (!state || !statement.plan)
		return;
	auto &context = input.context;
	if (!state->in_statement) {
		// Prepare(): no query is active and the text has not been seen. This plan cannot execute before
		// OnExecutePrepared forces a rebind inside a query, so only pre-screen it here.
		if (state->prepare_decided) {
			// The replacement gate already recorded this bind's denial (log-only) and let it continue.
			state->prepare_decided = false;
			return;
		}
		auto mode = ModeFor(LogOnlySetting(context));
		gatekeeper::Policy policy;
		gatekeeper::Result result;
		if (!ReadPolicy(context, policy, result)) {
			Decide(context, {mode, Boundary::PREPARE, nullptr, nullptr}, result);
			return;
		}
		result.allowed = true;
		try {
			CheckPlan(policy, policy, gatekeeper::BindingPolicy(), input.binder.GetStatementProperties(),
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
	if (!state->admitted) {
		// In ENFORCE mode the binding-boundary denial refused the statement before the engine could plan it;
		// should a plan arrive regardless, fail closed rather than authorize what was never admitted.
		state->result = {false, "forbidden", "", "", {{"statement", "not admitted at the binding boundary"}}};
		state->Record(context, Boundary::EXECUTION, &state->policy, &context.GetCurrentQuery());
		return;
	}
	if (!state->authorized) {
		// The engine's binder holds the values this statement's parameters were bound with (it binds them as
		// constants); authorize the admitted statement privately with exactly those values.
		case_insensitive_map_t<BoundParameterData> values;
		if (auto parameters = input.binder.GetParameters())
			values = parameters->GetParameterData();
		state->Authorize(context, &values);
		if (!state->authorized)
			return;
	}
	try {
		CheckPlan(state->policy, state->policy, state->binding, input.binder.GetStatementProperties(), *statement.plan,
		          state->result);
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

struct EnforceGlobalState : GlobalTableFunctionState {
	bool finished = false;
};

static unique_ptr<FunctionData> BindEnforce(ClientContext &, TableFunctionBindInput &, vector<LogicalType> &types,
                                            vector<string> &names) {
	types = {LogicalType::BOOLEAN, LogicalType::LIST(LogicalType::VARCHAR)};
	names = {"enforced", "warnings"};
	return make_uniq<EnforceBinding>();
}

static unique_ptr<GlobalTableFunctionState> InitEnforce(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<EnforceGlobalState>();
}

static void Enforce(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<EnforceGlobalState>();
	if (state.finished)
		return;
	// Latch at execution, never at bind: EXPLAIN and PREPARE must not enforce.
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

	TableFunction enforce("gatekeeper_enforce", {}, Enforce, BindEnforce, InitEnforce);
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
