#define DUCKDB_EXTENSION_MAIN
#include "gatekeeper_extension.hpp"
#include "check.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/materialized_query_result.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "enforcement.hpp"
#include "fuzz_checks.hpp"
#include "options.hpp"
#include "policy_setting.hpp"
#include "version.hpp"

namespace duckdb {

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

static void SetPolicy(ClientContext &, SetScope scope, Value &value) {
	// DuckDB's parser currently rejects SET LOCAL; refuse it here too so a future parser cannot route a
	// connection-scoped assignment into the instance-wide policy.
	if (scope == SetScope::SESSION || scope == SetScope::LOCAL)
		throw InvalidInputException("gatekeeper_policy is global-only");
	try {
		value = gatekeeper::PolicyValue(gatekeeper::ReadPolicy(value));
	} catch (const std::invalid_argument &error) {
		throw InvalidInputException(error.what());
	}
}

gatekeeper::Policy GlobalPolicy(ClientContext &context) {
	auto &config = DBConfig::GetConfig(context);
	Value value;
	if (!config.TryGetCurrentSetting(POLICY_SETTING, value))
		throw std::invalid_argument("gatekeeper_policy is unavailable");
	return gatekeeper::ReadPolicy(value);
}

struct ValidateBinding : FunctionData {
	Value sql;
	std::vector<std::pair<std::string, Value>> options;
	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<ValidateBinding>();
		result->sql = sql;
		result->options = options;
		return std::move(result);
	}
	bool Equals(const FunctionData &other) const override {
		auto &binding = other.Cast<ValidateBinding>();
		if (!Value::NotDistinctFrom(sql, binding.sql) || options.size() != binding.options.size())
			return false;
		for (idx_t i = 0; i < options.size(); i++)
			if (options[i].first != binding.options[i].first ||
			    !Value::NotDistinctFrom(options[i].second, binding.options[i].second))
				return false;
		return true;
	}
};

#ifdef GATEKEEPER_FUZZ
bool GatekeeperBindingsEqualForFuzz(const Value &left, const Value &right, bool option) {
	ValidateBinding a, b;
	a.sql = option ? Value("SELECT 1") : left;
	b.sql = option ? Value("SELECT 1") : right;
	if (option) {
		a.options.emplace_back("blocked_functions", left);
		b.options.emplace_back("blocked_functions", right);
	}
	return a.Equals(*b.Copy());
}
#endif

static unique_ptr<FunctionData> BindValidate(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &types,
                                             vector<string> &names) {
	// DuckDB overwrites duplicate named parameters before calling bind.
	if (input.ref.function &&
	    input.ref.function->Cast<FunctionExpression>().children.size() != input.named_parameters.size() + 1)
		throw BinderException("duplicate Gatekeeper option");
	auto result = make_uniq<ValidateBinding>();
	result->sql = input.inputs[0];
	for (const auto &option : input.named_parameters) {
		auto &name = option.first;
		auto value = option.second;
		try {
			gatekeeper::CheckOptionShape(name, value);
		} catch (const std::invalid_argument &error) {
			throw BinderException(error.what());
		}
		// ANY preserves nested field sets rather than silently coercing away unknown fields.
		result->options.emplace_back(name, std::move(value));
	}
	auto type = ResultType();
	for (const auto &field : StructType::GetChildTypes(type)) {
		names.push_back(field.first);
		types.push_back(field.second);
	}
	return std::move(result);
}

struct SingleRowState : GlobalTableFunctionState {
	bool finished = false;
};

static unique_ptr<GlobalTableFunctionState> InitSingleRow(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<SingleRowState>();
}

#ifdef GATEKEEPER_FUZZ
Value GatekeeperCheckForFuzz(ClientContext &context, const string &sql, const gatekeeper::Limits &limits) {
	Value result;
	context.RunFunctionInTransaction([&]() {
		auto policy = GlobalPolicy(context);
		result = ResultValue(Check(context, policy, policy, sql, limits));
	});
	return result;
}
#endif

static void GatekeeperValidate(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<SingleRowState>();
	if (state.finished)
		return;
	auto &binding = input.bind_data->Cast<ValidateBinding>();
	gatekeeper::Result decision;
	try {
		// Read policy and bind the SQL at execution, never cache a decision in bind data.
		auto defaults = GlobalPolicy(context);
		auto policy = defaults;
		gatekeeper::ApplyOptions(policy, binding.options);
		if (binding.sql.IsNull())
			decision = {false, "invalid_input", "", "NULL SQL input", {}};
		else
			decision = Check(context, policy, defaults, binding.sql.GetValue<string>());
	} catch (const std::invalid_argument &error) {
		decision = {false, "invalid_input", "", error.what(), {}};
	}
	auto result = ResultValue(decision);
	auto &fields = StructValue::GetChildren(result);
	for (idx_t column = 0; column < fields.size(); column++)
		output.SetValue(column, 0, fields[column]);
	output.SetCardinality(1);
	state.finished = true;
}

struct ConfigureBinding : FunctionData {
	Value policy;
	explicit ConfigureBinding(Value policy) : policy(std::move(policy)) {}
	unique_ptr<FunctionData> Copy() const override { return make_uniq<ConfigureBinding>(policy); }
	bool Equals(const FunctionData &other) const override { return policy == other.Cast<ConfigureBinding>().policy; }
};

static unique_ptr<FunctionData> BindConfigure(ClientContext &, TableFunctionBindInput &input,
                                              vector<LogicalType> &types, vector<string> &names) {
	try {
		// DuckDB overwrites duplicate named parameters in its map before calling bind.
		if (input.ref.function &&
		    input.ref.function->Cast<FunctionExpression>().children.size() != input.named_parameters.size())
			throw std::invalid_argument("duplicate Gatekeeper configuration option");
		gatekeeper::Policy policy;
		std::vector<std::pair<std::string, Value>> options;
		for (const auto &option : input.named_parameters)
			options.emplace_back(option.first, option.second);
		gatekeeper::ApplyOptions(policy, options);
		types.push_back(LogicalType::BOOLEAN);
		names.push_back("Success");
		return make_uniq<ConfigureBinding>(gatekeeper::PolicyValue(policy));
	} catch (const std::invalid_argument &error) {
		throw InvalidInputException(error.what());
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

// The grammar and serializer compiled into this artifact belong to exactly the engine it was built from.
// DuckDB stamps that engine into the extension footer and refuses others, but that check can be disabled
// with allow_extensions_metadata_mismatch, so refuse any other engine here as well. This mirrors the
// footer identity rather than a hardcoded release: the version tag for releases, the source id for dev
// builds, so community rebuilds against any engine checkout keep the guard without a source change.
//
// Distributed loadables statically link their own copy of DuckDB (EXTENSION_STATIC_BUILD), so inside this
// file DuckDB::LibraryVersion() and DuckDB::SourceID() report the build engine, never the host. The host's
// identity comes from its catalog: pragma_version() is bound to the host's implementation. A statically
// linked Gatekeeper is compiled into its host, so the check only exists in the loadable.
#ifdef DUCKDB_BUILD_LOADABLE_EXTENSION
struct BuildEngine {
	string version;
	string source_id;
};

static BuildEngine ParseBuildEngine() {
	// Read through a volatile pointer so the stamp stays one literal string in the binary rather than being
	// folded into immediates; that keeps it inspectable with `strings` and rewritable by the guard tests.
	const volatile char *stamp = gatekeeper::BUILD_ENGINE_STAMP;
	string text;
	for (; *stamp; stamp++) {
		text += *stamp;
	}
	auto parts = StringUtil::Split(text, ' ');
	if (parts.size() != 3 || parts[0] != "GATEKEEPER_BUILD_ENGINE") {
		throw InvalidInputException("Gatekeeper %s has a malformed build engine stamp: %s", gatekeeper::VERSION, text);
	}
	return {parts[1], parts[2]};
}

static void CheckBuildEngine(DatabaseInstance &db) {
	string host_version, host_source_id;
	try {
		Connection con(db);
		// Fully qualified: a host macro named pragma_version in the default catalog would otherwise shadow the
		// builtin and could report whatever engine identity the guard is looking for.
		auto result = con.Query("SELECT library_version, source_id FROM system.main.pragma_version()");
		if (result->HasError()) {
			result->ThrowError();
		}
		if (result->RowCount() != 1) {
			throw InvalidInputException("pragma_version() returned %llu rows", result->RowCount());
		}
		host_version = result->GetValue(0, 0).ToString();
		host_source_id = result->GetValue(1, 0).ToString();
	} catch (std::exception &error) {
		throw InvalidInputException("Gatekeeper %s cannot determine the host DuckDB engine: %s", gatekeeper::VERSION,
		                            error.what());
	}
	auto build = ParseBuildEngine();
	// DuckDB identifies release engines by version tag and dev engines by source id. Both sides must be the
	// same kind and agree on that field; a dev artifact from the release commit is still a different footer.
	const bool build_release = build.version.find("-dev") == string::npos;
	const bool host_release = host_version.find("-dev") == string::npos;
	const string &expected = build_release ? build.version : build.source_id;
	const string &actual = host_release ? host_version : host_source_id;
	if (build_release != host_release || actual != expected) {
		throw InvalidInputException("Gatekeeper %s was built for DuckDB %s (%s); this engine is %s (%s)",
		                            gatekeeper::VERSION, build.version, build.source_id, host_version, host_source_id);
	}
}
#endif

static void LoadInternal(ExtensionLoader &loader) {
#ifdef DUCKDB_BUILD_LOADABLE_EXTENSION
	CheckBuildEngine(loader.GetDatabaseInstance());
#endif
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	auto default_policy = gatekeeper::PolicyValue(gatekeeper::Policy());
	config.AddExtensionOption(POLICY_SETTING, "Global Gatekeeper authorization ceiling", default_policy.type(),
	                          default_policy, SetPolicy, SetScope::GLOBAL);
	// First position: decide replacement scans before any other callback's reader can bind.
	InstallReplacementScan(config);
	TableFunction validate("gatekeeper_validate", {LogicalType::VARCHAR}, GatekeeperValidate, BindValidate,
	                       InitSingleRow);
	TableFunction configure("gatekeeper_configure", {}, Configure, BindConfigure, InitSingleRow);
	for (const auto &name : gatekeeper::OptionNames()) {
		validate.named_parameters[name] = LogicalType::ANY;
		configure.named_parameters[name] = LogicalType::ANY;
	}
	// Descriptions and examples feed duckdb_functions(), which the community-extensions site renders as
	// the "Added Functions" table for this extension. Function entries do not keep CreateInfo::comment.
	// The generator keeps only the first line of each description and shows it in one table cell, so keep
	// these to a single short sentence and do not add newlines. Parameter names are paired positionally
	// with named_parameters, an unordered map, so they are listed in OptionNames() order; this is only
	// safe because every named option is ANY (pinned by test_documentation.py).
	FunctionDescription validate_description;
	validate_description.parameter_types = {LogicalType::VARCHAR};
	validate_description.parameter_names = {"sql"};
	validate_description.description = "Validates one untrusted read-only SQL statement against the global policy "
	                                   "and the request options without executing it.";
	validate_description.examples = {
	    "SELECT allowed, code FROM gatekeeper_validate('SELECT sum(amount) FROM "
	    "reporting.orders', allowed_tables := [{schema: 'reporting', 'table': 'orders'}])"};
	FunctionDescription configure_description;
	configure_description.description =
	    "Replaces the global Gatekeeper policy atomically; omitted options revert to the built-in defaults.";
	configure_description.examples = {"CALL gatekeeper_configure(allowed_tables := [{schema: 'reporting', 'table': "
	                                  "'*'}], blocked_functions := ['md5'])"};
	for (const auto &name : gatekeeper::OptionNames()) {
		validate_description.parameter_names.push_back(name);
		configure_description.parameter_names.push_back(name);
	}
	CreateTableFunctionInfo validate_info(std::move(validate));
	validate_info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	validate_info.descriptions.push_back(std::move(validate_description));
	CreateTableFunctionInfo configure_info(std::move(configure));
	configure_info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	configure_info.descriptions.push_back(std::move(configure_description));
	loader.RegisterFunction(std::move(validate_info));
	loader.RegisterFunction(std::move(configure_info));
	RegisterEnforcement(loader);
}
void GatekeeperExtension::Load(ExtensionLoader &loader) { LoadInternal(loader); }
std::string GatekeeperExtension::Name() { return "gatekeeper"; }
std::string GatekeeperExtension::Version() const { return gatekeeper::VERSION; }
} // namespace duckdb
extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(gatekeeper, loader) { duckdb::LoadInternal(loader); }
}
