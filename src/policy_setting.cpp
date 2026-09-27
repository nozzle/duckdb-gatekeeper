#include "policy_setting.hpp"
#include "audit.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "engine_api.hpp"
#include "options.hpp"
#include "single_row.hpp"

namespace duckdb {

static void SetPolicy(ClientContext &context, SetScope scope, Value &value) {
	// DuckDB's parser currently rejects SET LOCAL; refuse it here too so a future parser cannot route a
	// connection-scoped assignment into the instance-wide policy.
	if (scope == SetScope::SESSION || scope == SetScope::LOCAL)
		throw InvalidInputException("gatekeeper_policy is global-only");
	gatekeeper::Policy policy;
	try {
		policy = gatekeeper::ReadPolicy(value);
	} catch (const std::invalid_argument &error) {
		throw InvalidInputException(error.what());
	}
	value = gatekeeper::PolicyValue(policy);
	LogSettingChange(context, "policy_changed", value, &policy);
}

gatekeeper::Policy GlobalPolicy(ClientContext &context) {
	auto &config = DBConfig::GetConfig(context);
	Value value;
	if (!config.TryGetCurrentSetting(POLICY_SETTING, value))
		throw std::invalid_argument("gatekeeper_policy is unavailable");
	return gatekeeper::ReadPolicy(value);
}

bool TryGlobalPolicy(ClientContext &context, gatekeeper::Policy &policy, gatekeeper::Result &result) {
	try {
		policy = GlobalPolicy(context);
		return true;
	} catch (const std::invalid_argument &error) {
		result = gatekeeper::InvalidInput(string("cannot read the global policy: ") + error.what());
		return false;
	}
}

struct ConfigureBinding : FunctionData {
	Value policy;
	explicit ConfigureBinding(Value policy) : policy(std::move(policy)) {}
	unique_ptr<FunctionData> Copy() const override { return make_uniq<ConfigureBinding>(policy); }
	bool Equals(const FunctionData &other) const override { return policy == other.Cast<ConfigureBinding>().policy; }
};

static unique_ptr<FunctionData> BindConfigure(ClientContext &, TableFunctionBindInput &input,
                                              vector<LogicalType> &types, engine::NameList &names) {
	engine::RunAtOnce(input);
	try {
		// DuckDB overwrites duplicate named parameters in its map before calling bind.
		if (input.ref.function &&
		    engine::ArgumentCount(input.ref.function->Cast<FunctionExpression>()) != input.named_parameters.size())
			throw std::invalid_argument("duplicate Gatekeeper option");
		gatekeeper::Policy policy;
		std::vector<std::pair<std::string, Value>> options;
		for (const auto &option : input.named_parameters)
			options.emplace_back(engine::Str(option.first), option.second);
		gatekeeper::ApplyArguments(policy, options);
		types.push_back(LogicalType::BOOLEAN);
		names.push_back("Success");
		return make_uniq<ConfigureBinding>(gatekeeper::PolicyValue(policy));
	} catch (const std::invalid_argument &error) {
		// A bad option name, shape, or value is a bind error for CALL gatekeeper_configure(...) as it is for
		// gatekeeper_validate(...); the policy is unchanged either way.
		throw BinderException(error.what());
	}
}

static void Configure(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<SingleRowState>();
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

void RegisterPolicySetting(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	auto default_policy = gatekeeper::PolicyValue(gatekeeper::Policy());
	config.AddExtensionOption(POLICY_SETTING, "Global Gatekeeper authorization ceiling", default_policy.type(),
	                          default_policy, SetPolicy, SetScope::GLOBAL);
	TableFunction configure("gatekeeper_configure", {}, Configure, BindConfigure, InitSingleRow);
	for (const auto &name : gatekeeper::OptionNames())
		configure.named_parameters[engine::ToName(name)] = LogicalType::ANY;
	configure.named_parameters["json"] = LogicalType::ANY;
	// One short sentence and no newlines; parameter names in OptionNames() order. See the description of
	// gatekeeper_validate in gatekeeper_extension.cpp for why.
	FunctionDescription description;
	description.description =
	    "Replaces the global Gatekeeper policy atomically; omitted options revert to the built-in defaults.";
	description.examples = {"CALL gatekeeper_configure(allowed_tables := [{schema_path: ['reporting'], 'table': "
	                        "'*'}], blocked_functions := [{catalog:'system', schema_path:['main'], name:'md5'}])"};
	for (const auto &name : gatekeeper::OptionNames())
		description.parameter_names.push_back(name);
	description.parameter_names.push_back("json");
	CreateTableFunctionInfo info(std::move(configure));
	info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	info.descriptions.push_back(std::move(description));
	loader.RegisterFunction(std::move(info));
}
} // namespace duckdb
