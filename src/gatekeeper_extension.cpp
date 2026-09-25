#define DUCKDB_EXTENSION_MAIN
#include "gatekeeper_extension.hpp"
#include "audit.hpp"
#include "check.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/query_result.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "enforcement.hpp"
#include "engine_api.hpp"
#include "fuzz_checks.hpp"
#include "options.hpp"
#include "policy_setting.hpp"
#include "result_value.hpp"
#include "single_row.hpp"
#include "version.hpp"

namespace duckdb {

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
                                             engine::NameList &names) {
	// DuckDB overwrites duplicate named parameters before calling bind.
	if (input.ref.function &&
	    engine::ArgumentCount(input.ref.function->Cast<FunctionExpression>()) != input.named_parameters.size() + 1)
		throw BinderException("duplicate Gatekeeper option");
	auto result = make_uniq<ValidateBinding>();
	result->sql = input.inputs[0];
	for (const auto &option : input.named_parameters) {
		auto &name = engine::Str(option.first);
		auto value = option.second;
		// ANY preserves nested field sets rather than silently coercing away unknown fields.
		result->options.emplace_back(name, std::move(value));
	}
	try {
		gatekeeper::CheckArguments(result->options);
	} catch (const std::invalid_argument &error) {
		throw BinderException(error.what());
	}
	auto type = ResultType();
	for (const auto &field : StructType::GetChildTypes(type)) {
		names.push_back(field.first);
		types.push_back(field.second);
	}
	return std::move(result);
}

#ifdef GATEKEEPER_FUZZ
Value GatekeeperCheckForFuzz(ClientContext &context, const string &sql, const gatekeeper::Limits &limits) {
	Value result;
	context.RunFunctionInTransaction([&]() {
		auto policy = GlobalPolicy(context);
		result = ResultValue(Check(context, {policy, policy}, sql, limits));
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
	string sql = binding.sql.IsNull() ? string() : binding.sql.GetValue<string>();
	// The record names the global ceiling, not the request layer: that is the policy the host set and the one
	// policy_changed records describe.
	gatekeeper::Policy defaults;
	bool have_defaults = false;
	try {
		// Read policy and bind the SQL at execution, never cache a decision in bind data.
		defaults = GlobalPolicy(context);
		have_defaults = true;
		auto policy = defaults;
		gatekeeper::ApplyArguments(policy, binding.options);
		if (binding.sql.IsNull())
			decision = gatekeeper::InvalidInput("NULL SQL input");
		else
			decision = Check(context, {defaults, policy}, sql);
	} catch (const std::invalid_argument &error) {
		decision = gatekeeper::InvalidInput(error.what());
	}
	Decide(context,
	       {DecisionMode::VALIDATE, Boundary::NONE, have_defaults ? &defaults : nullptr,
	        binding.sql.IsNull() ? nullptr : &sql},
	       decision);
	auto result = ResultValue(decision);
	auto &fields = StructValue::GetChildren(result);
	for (idx_t column = 0; column < fields.size(); column++)
		output.SetValue(column, 0, fields[column]);
	output.SetCardinality(1);
	state.finished = true;
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
// linked Gatekeeper is compiled into its host, so the check only exists in the loadable. GATEKEEPER_LOADABLE
// is Gatekeeper's own marker for that target (CMakeLists.txt); it does not depend on which build defines
// the engine happens to emit.
#ifdef GATEKEEPER_LOADABLE
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
#ifdef GATEKEEPER_LOADABLE
	CheckBuildEngine(loader.GetDatabaseInstance());
#endif
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	RegisterPolicySetting(loader);
	// First position: decide replacement scans before any other callback's reader can bind.
	InstallReplacementScan(config);
	TableFunction validate("gatekeeper_validate", {LogicalType::VARCHAR}, GatekeeperValidate, BindValidate,
	                       InitSingleRow);
	for (const auto &name : gatekeeper::OptionNames())
		validate.named_parameters[engine::ToName(name)] = LogicalType::ANY;
	validate.named_parameters["json"] = LogicalType::ANY;
	// Descriptions and examples feed duckdb_functions(), which the community-extensions site renders as
	// the "Added Functions" table for this extension. Function entries do not keep CreateInfo::comment.
	// The generator keeps only the first line of each description and shows it in one table cell, so keep
	// these to a single short sentence and do not add newlines. Parameter names are paired positionally
	// with named_parameters, an unordered map, so they are listed in OptionNames() order; this is only
	// safe because every named option is ANY (pinned by test_documentation.py).
	FunctionDescription description;
	description.parameter_types = {LogicalType::VARCHAR};
	description.parameter_names = {"sql"};
	description.description = "Validates one untrusted read-only SQL statement against the global policy "
	                          "and the request options without executing it.";
	description.examples = {"SELECT allowed, code FROM gatekeeper_validate('SELECT sum(amount) FROM "
	                        "reporting.orders', allowed_tables := [{schema_path: ['reporting'], 'table': 'orders'}])"};
	for (const auto &name : gatekeeper::OptionNames())
		description.parameter_names.push_back(name);
	description.parameter_names.push_back("json");
	CreateTableFunctionInfo info(std::move(validate));
	info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	info.descriptions.push_back(std::move(description));
	loader.RegisterFunction(std::move(info));
	RegisterAudit(loader);
	RegisterEnforcement(loader);
}
void GatekeeperExtension::Load(ExtensionLoader &loader) { LoadInternal(loader); }
std::string GatekeeperExtension::Name() { return "gatekeeper"; }
std::string GatekeeperExtension::Version() const { return gatekeeper::VERSION; }
} // namespace duckdb
extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(gatekeeper, loader) { duckdb::LoadInternal(loader); }
}
