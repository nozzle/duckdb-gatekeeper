#include "enforcement.hpp"
#include "audit.hpp"
#include "check.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/connection_manager.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/prepared_statement_data.hpp"
#include "duckdb/main/settings.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/extension_callback.hpp"
#include "duckdb/planner/planner_extension.hpp"
#include "policy_setting.hpp"

namespace duckdb {

static constexpr const char *ENFORCEMENT_SETTING = "gatekeeper_enforcement";
static constexpr const char *STATE_KEY = "gatekeeper_enforcement";

enum class EnforcementMode { OFF, NEW_CONNECTIONS, ALL };

// Anything other than the two recognized permissive spellings enforces everything. Native option writes
// bypass the SET callback below, so an unrecognized value means the setting was written without
// validation; a sandbox fails closed in that case.
static EnforcementMode ParseMode(const Value &value) {
	if (value.IsNull())
		return EnforcementMode::ALL;
	auto text = StringUtil::Lower(value.ToString());
	if (text == "off")
		return EnforcementMode::OFF;
	if (text == "new_connections")
		return EnforcementMode::NEW_CONNECTIONS;
	return EnforcementMode::ALL;
}

static EnforcementMode CurrentMode(DBConfig &config) {
	Value value;
	if (!config.TryGetCurrentSetting(ENFORCEMENT_SETTING, value))
		return EnforcementMode::OFF;
	return ParseMode(value);
}

static DecisionSite Site(Boundary boundary, optional_ptr<const gatekeeper::Policy> policy,
                         optional_ptr<const string> sql) {
	return {DecisionMode::ENFORCE, boundary, policy, sql};
}

// Reads the policy snapshot for this statement. An unreadable setting refuses the statement as invalid_input:
// the fail-closed outcome for a sandbox whose policy was written without validation.
static bool SnapshotPolicy(ClientContext &context, Boundary boundary, optional_ptr<const string> sql,
                           gatekeeper::Policy &policy, gatekeeper::Result &result) {
	try {
		policy = GlobalPolicy(context);
		return true;
	} catch (const std::invalid_argument &error) {
		result = {false, "invalid_input", "", string("cannot read the global policy: ") + error.what()};
		Decide(context, Site(boundary, nullptr, sql), result);
		return false;
	}
}

// The per-connection latch. Its presence in ClientContext::registered_state is what makes a connection
// enforced; nothing removes it. Within one query it carries the decision between the engine hooks.
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
struct EnforcementState : ClientContextState {
	gatekeeper::Policy policy; // one snapshot for the whole statement
	gatekeeper::Result result; // the decision in progress
	bool admitted = false;     // text passed the binding boundary
	bool authorized = false;   // private bind with catalog authorization passed
	gatekeeper::BindingPolicy binding;
	unique_ptr<SQLStatement> statement; // admitted statement awaiting parameter values

	void Reset() {
		policy = gatekeeper::Policy();
		result = gatekeeper::Result();
		admitted = false;
		authorized = false;
		binding = gatekeeper::BindingPolicy();
		statement.reset();
	}
	// Runs the same private authorization gatekeeper_validate performs. Engine errors (missing tables, type
	// errors) propagate unchanged so the caller gets DuckDB's own message; they are not decisions.
	void Authorize(ClientContext &context, optional_ptr<const case_insensitive_map_t<BoundParameterData>> parameters) {
		try {
			duckdb::Authorize(context, policy, policy, *statement, binding, parameters, result);
		} catch (const PermissionException &) {
			MarkDenied(result);
			Decide(context, Site(Boundary::AUTHORIZE, &policy, &context.GetCurrentQuery()), result);
			return;
		}
		authorized = true;
	}
	void QueryBegin(ClientContext &context) override {
		Reset();
		const auto &sql = context.GetCurrentQuery();
		if (!SnapshotPolicy(context, Boundary::BINDING, &sql, policy, result))
			return;
		TextCheck text;
		try {
			text = CheckText(context, policy, policy, sql, gatekeeper::Limits());
		} catch (const ParserException &error) {
			result = {false, "parser", "parser", ErrorData(error).RawMessage()};
			Decide(context, Site(Boundary::BINDING, &policy, &sql), result);
			return;
		} catch (const InvalidInputException &error) {
			result = {false, "invalid_input", "", ErrorData(error).RawMessage()};
			Decide(context, Site(Boundary::BINDING, &policy, &sql), result);
			return;
		}
		result = std::move(text.result);
		if (!result.allowed) {
			Decide(context, Site(Boundary::BINDING, &policy, &sql), result);
			return;
		}
		admitted = true;
		binding = std::move(text.binding);
		statement = std::move(text.statements[0]); // MAX_STATEMENTS is 1
		if (statement->named_param_map.empty())
			Authorize(context, nullptr);
	}
	void QueryEnd(ClientContext &, optional_ptr<ErrorData>) override { Reset(); }
	RebindQueryInfo OnExecutePrepared(ClientContext &context, PreparedStatementCallbackInfo &,
	                                  RebindQueryInfo) override {
		if (!admitted) {
			result = {false, "forbidden", "", "", {{"statement", "not admitted at the binding boundary"}}};
			Decide(context, Site(Boundary::BINDING, &policy, &context.GetCurrentQuery()), result);
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

bool IsEnforced(ClientContext &context) { return StateOf(context) != nullptr; }

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
	if (!state->admitted) {
		// Prepare(): no query is active and the text has not been seen. This plan cannot execute before
		// OnExecutePrepared forces a rebind inside a query, so only pre-screen it here.
		gatekeeper::Policy policy;
		gatekeeper::Result result;
		if (!SnapshotPolicy(context, Boundary::PREPARE, nullptr, policy, result))
			return;
		result.allowed = true;
		try {
			CheckPlan(policy, policy, gatekeeper::BindingPolicy(), input.binder.GetStatementProperties(),
			          *statement.plan, result);
		} catch (const PermissionException &) {
			MarkDenied(result);
			Decide(context, Site(Boundary::PREPARE, &policy, nullptr), result);
		}
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
	Decide(context, Site(Boundary::EXECUTION, &state->policy, &context.GetCurrentQuery()), state->result);
}

struct EnforcementCallback : ExtensionCallback {
	void OnConnectionOpened(ClientContext &context) override {
		if (CurrentMode(DBConfig::GetConfig(context)) != EnforcementMode::OFF)
			Latch(context);
	}
};

static void SetEnforcement(ClientContext &context, SetScope scope, Value &value) {
	if (scope == SetScope::SESSION || scope == SetScope::LOCAL)
		throw InvalidInputException("gatekeeper_enforcement is global-only");
	auto text = value.IsNull() ? string() : StringUtil::Lower(value.ToString());
	if (text != "off" && text != "new_connections" && text != "all")
		throw InvalidInputException("gatekeeper_enforcement must be 'off', 'new_connections', or 'all'");
	value = Value(text);
	// Publish the mode now rather than when PhysicalSet stores it after this callback returns: a
	// connection that opens in between must already see the new mode in OnConnectionOpened. The later
	// store writes the same value again.
	DBConfig::GetConfig(context).SetOption(ENFORCEMENT_SETTING, value);
	LogSettingChange(context, "enforcement_changed", value);
	if (text == "all") {
		// Every connection open now, including the one issuing this SET. A connection that opened before
		// this snapshot is in it; one that opens after it was latched by OnConnectionOpened because the
		// mode is already published. Returning to another mode never releases a latch.
		for (auto &connection : DatabaseInstance::GetDatabase(context).GetConnectionManager().GetConnectionList())
			Latch(*connection);
	}
}

// Host settings Gatekeeper documents but deliberately never changes. Reported, not enforced.
static vector<string> PostureWarnings(ClientContext &context) {
	auto &config = DBConfig::GetConfig(context);
	vector<string> warnings;
	if (Settings::Get<EnableExternalAccessSetting>(config))
		warnings.push_back("enable_external_access is true: readers reached through trusted views or macros can "
		                   "open files and URLs while binding");
	if (Settings::Get<AutoloadKnownExtensionsSetting>(config) ||
	    Settings::Get<AutoinstallKnownExtensionsSetting>(config))
		warnings.push_back("autoload_known_extensions or autoinstall_known_extensions is true: binding can load "
		                   "extensions on demand");
	if (!Settings::Get<LockConfigurationSetting>(config))
		warnings.push_back("lock_configuration is false: unenforced connections can still change gatekeeper_policy "
		                   "and gatekeeper_enforcement");
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
	config.AddExtensionOption(ENFORCEMENT_SETTING,
	                          "Which connections Gatekeeper enforces its policy on: off, new_connections, or all",
	                          LogicalType::VARCHAR, Value("off"), SetEnforcement, SetScope::GLOBAL);
	PlannerExtension planner;
	planner.post_bind_function = PostBind;
	PlannerExtension::Register(config, planner);
	ExtensionCallback::Register(config, make_shared_ptr<EnforcementCallback>());

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
