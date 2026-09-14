#define DUCKDB_EXTENSION_MAIN
#include "gatekeeper_extension.hpp"
#include "authorization.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/function/replacement_scan.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/bound_parameter_map.hpp"
#include "engine_errors.hpp"
#include "function_policy.hpp"
#include "fuzz_checks.hpp"
#include "json_serializer.hpp"
#include "options.hpp"
#include "version.hpp"

namespace duckdb {
using namespace duckdb_yyjson;

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

static constexpr const char *POLICY_SETTING = "gatekeeper_policy";

static void SetPolicy(ClientContext &, SetScope scope, Value &value) {
	if (scope == SetScope::SESSION)
		throw InvalidInputException("gatekeeper_policy is global-only");
	try {
		value = gatekeeper::PolicyValue(gatekeeper::ReadPolicy(value));
	} catch (const std::invalid_argument &error) {
		throw InvalidInputException(error.what());
	}
}

static gatekeeper::Policy GlobalPolicy(ClientContext &context) {
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

// Replacement scans run when a table name resolves to no catalog object. DuckDB's callbacks only
// construct a TableRef; the reader binds (and may open files) afterwards. Gatekeeper installs the
// first callback at LOAD and, while a validation is binding on this thread, decides before that
// bind happens: the resolved reader is authorized like a caller-written table function in both layers.
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
	if (!scope || &context != &scope->context)
		return nullptr; // Ordinary connections, including reentrant ones on this thread, are unaffected.
	auto path = ReplacementScan::GetFullPath(input);
	auto deny = [&](const string &rule, const string &message, const string &function = "") {
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
		for (const auto *layer : {&scope->ceiling, &scope->policy}) {
			if (!gatekeeper::FunctionAllowed(*layer, name))
				deny("function", "replacement scan function is not allowed: " + gatekeeper::CanonicalFunction(name),
				     gatekeeper::CanonicalFunction(name));
		}
		scope->authorized.insert(gatekeeper::Lower(input.table_name));
		scope->result.objects.insert({"", "", path, "replacement"});
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

static gatekeeper::Result Check(ClientContext &context, const gatekeeper::Policy &policy,
                                const gatekeeper::Policy &ceiling, const string &sql,
                                const gatekeeper::Limits &limits = gatekeeper::Limits()) {
	gatekeeper::Result result;
	bool binding = false;
	try {
		if (sql.find('\0') != string::npos)
			throw InvalidInputException("SQL contains a NUL byte");
		if (sql.size() > limits.bytes)
			return {false, "forbidden", "", "", {{"limit", "SQL exceeds fixed input size limit"}}};
		Parser parser(context.GetParserOptions());
		parser.ParseQuery(sql);
		if (parser.statements.empty())
			throw InvalidInputException("SQL contains no statements");
		if (parser.statements.size() > gatekeeper::MAX_STATEMENTS)
			return {false, "forbidden", "", "", {{"limit", "statement count exceeds fixed limit"}}};
		unique_ptr<yyjson_mut_doc, decltype(&yyjson_mut_doc_free)> doc(yyjson_mut_doc_new(nullptr),
		                                                               yyjson_mut_doc_free);
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
			if (statement->type != StatementType::SELECT_STATEMENT)
				return {false, "unsupported", "", "", {{"statement", "only supported read statements are permitted"}}};
			yyjson_mut_arr_append(statements, JsonSerializer::Serialize(statement->Cast<SelectStatement>(), doc.get(),
			                                                            true, true, true, serialization_options));
		}
		unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> ast(yyjson_mut_doc_imut_copy(doc.get(), nullptr),
		                                                       yyjson_doc_free);
		if (!ast)
			throw std::bad_alloc();
		size_t bytes = 0;
		unique_ptr<char, decltype(&free)> serialized(yyjson_write(ast.get(), 0, &bytes), free);
		if (!serialized)
			throw std::bad_alloc();
		if (bytes > limits.bytes)
			return {false, "forbidden", "", "", {{"limit", "serialized AST exceeds fixed size limit"}}};
		gatekeeper::BindingPolicy binding_policy;
		result = gatekeeper::Validate(yyjson_doc_get_root(ast.get()), policy, &binding_policy, &ceiling, limits);
		if (!result.allowed)
			return result;
		binding = true;
		for (auto &statement : parser.statements) {
			case_insensitive_map_t<BoundParameterData> parameter_data;
			BoundParameterMap parameters(parameter_data);
			auto binder = Binder::CreateBinder(context);
			binder->SetParameters(parameters);
			binder->SetBindingMode(BindingMode::EXTRACT_REPLACEMENT_SCANS);
			binder->SetCatalogLookupCallback([&](CatalogEntry &entry) {
				AuthorizeObject(ceiling, binding_policy, entry, result);
				AuthorizeObject(policy, binding_policy, entry, result);
			});
			ValidationScope scope{context, policy, ceiling, result, {}};
			BoundStatement bound;
			{
				ScopeGuard guard(scope);
				bound = binder->Bind(*statement);
			}
			// Unlike Planner::CreatePlan, never turn ParameterNotResolved into a partial success.
			// parameters.rebind is a cache hint, not incomplete binding.
			if (!bound.plan)
				throw BinderException(
				    "Validation requires a complete bound plan; parameter values or types may be needed");
			// Some bind callbacks return placeholder plans instead of throwing ParameterNotResolved.
			// Mirror Planner's bound_all_parameters type check: execution must not choose a different
			// implementation after validation by resolving an UNKNOWN parameter for the first time.
			for (const auto &entry : parameters.GetParameters())
				if (!entry.second->return_type.IsValid())
					throw BinderException(
					    "Validation requires a complete bound plan; parameter values or types may be needed");
			AuthorizePlan(ceiling, binding_policy, *bound.plan, result);
			AuthorizePlan(policy, binding_policy, *bound.plan, result);
			// Backstop: every replacement DuckDB recorded must have passed the Gatekeeper callback.
			for (auto &entry : binder->GetReplacementScans())
				if (!scope.authorized.count(gatekeeper::Lower(entry.first)))
					result.violations.emplace("replacement_scan", "replacement scan was not authorized: " + entry.first,
					                          "", "", entry.first);
			if (!result.violations.empty())
				throw PermissionException("unauthorized replacement scan");
		}
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

// The grammar and inventory are generated from exactly this engine release. DuckDB's own footer check
// compares the same string but can be disabled with allow_extensions_metadata_mismatch, so refuse to
// load into any other engine build here as well.
static void LoadInternal(ExtensionLoader &loader) {
	if (string(DuckDB::LibraryVersion()) != gatekeeper::DUCKDB_VERSION) {
		throw InvalidInputException("Gatekeeper %s supports DuckDB %s only; this engine is %s", gatekeeper::VERSION,
		                            gatekeeper::DUCKDB_VERSION, DuckDB::LibraryVersion());
	}
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	auto default_policy = gatekeeper::PolicyValue(gatekeeper::Policy());
	config.AddExtensionOption(POLICY_SETTING, "Global Gatekeeper authorization ceiling", default_policy.type(),
	                          default_policy, SetPolicy, SetScope::GLOBAL);
	// First position: decide replacement scans before any other callback's reader can bind.
	bool installed = false;
	for (auto &scan : config.replacement_scans)
		installed = installed || scan.function == GatekeeperReplacementScan;
	if (!installed)
		config.replacement_scans.insert(config.replacement_scans.begin(), ReplacementScan(GatekeeperReplacementScan));
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
}
void GatekeeperExtension::Load(ExtensionLoader &loader) { LoadInternal(loader); }
std::string GatekeeperExtension::Name() { return "gatekeeper"; }
std::string GatekeeperExtension::Version() const { return gatekeeper::VERSION; }
} // namespace duckdb
extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(gatekeeper, loader) { duckdb::LoadInternal(loader); }
}
