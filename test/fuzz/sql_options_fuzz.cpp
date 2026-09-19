#include "authorization.hpp"
#include "duckdb.hpp"
#include "duckdb/function/replacement_scan.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/planner/operator/logical_projection.hpp"
#include "engine_errors.hpp"
#include "fuzz_checks.hpp"
#include "options.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace duckdb;

static void CheckError(ExceptionType type) {
	if (gatekeeper::PropagateEngineError(type))
		std::abort();
}

static void Setup(Connection &connection) {
	// Logging at DEBUG records every decision, allowed ones included, so the record path runs under the
	// sanitizers for each input. In-memory storage is truncated per input in CheckEnforcedParity.
	auto result = connection.Query(
	    "SET enable_external_access=false; SET autoload_known_extensions=false; SET "
	    "autoinstall_known_extensions=false; "
	    "SET threads=1; CREATE TABLE t(x INTEGER); CREATE SCHEMA secret; CREATE TABLE secret.t(x INTEGER); "
	    "CREATE VIEW v AS SELECT * FROM t; CALL enable_logging('Gatekeeper'); SET logging_level='debug'");
	for (QueryResult *current = result.get(); current; current = current->next.get()) {
		if (current->HasError())
			std::abort();
	}
}

static Value Decision(QueryResult &result) {
	if (result.HasError()) {
		CheckError(result.GetErrorObject().Type());
		// Binder/type/invalid-option exceptions are expected, but must be deterministic too.
		return Value::STRUCT({{"type", Value(int64_t(result.GetErrorObject().Type()))},
		                      {"error", Value(result.GetErrorObject().RawMessage())}});
	}
	auto chunk = result.Fetch();
	if (!chunk || chunk->size() != 1)
		std::abort();
	if (chunk->ColumnCount() != 8)
		std::abort();
	child_list_t<Value> columns;
	for (idx_t i = 0; i < chunk->ColumnCount(); i++)
		columns.emplace_back(result.names[i], chunk->GetValue(i, 0));
	auto value = Value::STRUCT(std::move(columns));
	auto extra = result.Fetch();
	if (extra && extra->size())
		std::abort();
	auto &fields = StructValue::GetChildren(value);
	if (fields.size() != 8)
		std::abort();
	for (size_t i : {size_t(6), size_t(7)}) {
		const auto &entries = ListValue::GetChildren(fields[i]);
		if (!fields[0].GetValue<bool>() && !entries.empty())
			std::abort();
		std::vector<std::string> previous;
		for (const auto &entry : entries) {
			std::vector<std::string> current;
			for (const auto &part : StructValue::GetChildren(entry)) {
				if (part.IsNull())
					std::abort();
				current.push_back(part.GetValue<std::string>());
			}
			if (current.size() != 4 || (!previous.empty() && !(previous < current)))
				std::abort();
			previous = current;
		}
	}
	const auto code = fields[1].GetValue<std::string>();
	const auto &violations = ListValue::GetChildren(fields[2]);
	const auto error = fields[4].GetValue<std::string>();
	if (fields[0].GetValue<bool>() != (code == "ok"))
		std::abort();
	if (code == "ok") {
		if (!violations.empty() || !error.empty())
			std::abort();
	} else if (code == "forbidden" || code == "unsupported") {
		if (violations.empty() || !error.empty())
			std::abort();
	} else if (code == "parser" || code == "binding" || code == "invalid_input") {
		if (!violations.empty() || error.empty())
			std::abort();
	} else {
		std::abort();
	}
	if (!fields[5].IsNull()) {
		if (fields[5].GetValue<int64_t>() < 0)
			std::abort();
		bool carried = code == "parser";
		for (const auto &violation : violations) {
			auto &position = StructValue::GetChildren(violation)[6];
			carried = carried || (!position.IsNull() && position == fields[5]);
		}
		if (!carried)
			std::abort();
	}
	return value;
}

static std::string Option(uint8_t selector, const std::string &text) {
	const auto &names = gatekeeper::OptionNames();
	if (selector % (names.size() + 1) < names.size())
		return names[selector % (names.size() + 1)];
	// Arbitrary option names remain one quoted identifier, never executable SQL.
	std::string name = "\"";
	for (auto c : text) {
		if (c == '"')
			name += '"';
		name += c;
	}
	return name + '"';
}

static std::string Argument(uint8_t selector) {
	static const char *values[] = {
	    "$1",
	    "NULL",
	    "true",
	    "false",
	    "$2",
	    "0",
	    "-1",
	    "1.5",
	    "[]::VARCHAR[]",
	    "[$1]",
	    "[NULL]",
	    "[1]",
	    "[{schema:'main', 'table':$1}]",
	    "[{catalog:'memory', schema:'main', 'table':$1}]",
	    "[{catalog:NULL, schema:'main', 'table':$1}]",
	    "[{schema:NULL, 'table':$1}]",
	    "[{'table':$1}]",
	    "[{schema:'main', 'table':$1, extra:'x'}]",
	    "[{schema:'main', 'table':[$1]}]",
	    "[{schema:'main', 'table':{nested:$1}}]",
	    "[{schema:'main', 'table':1}]",
	    "[NULL::STRUCT(schema VARCHAR, \"table\" VARCHAR)]",
	    "{schema:'main', 'table':$1}",
	    "['main','secret']",
	    "['md5','read_csv','query_table']",
	    "[]",
	    "['sum']",
	    "['lower']",
	    "[{catalog:'memory', schema:'main', 'table':'t'}]",
	    "['unnest']",
	    "[{catalog:'*', schema:'main', 'table':'*'}]",
	    "[{catalog:'memory', schema:'*', 'table':$1}]",
	    "[{catalog:'*', schema:'*', 'table':'*'}]",
	    "[{catalog:'memory', schema:'main', 'table':'*'}, {catalog:'*', schema:'secret', 'table':$1}]"};
	return values[selector % (sizeof(values) / sizeof(values[0]))];
}

static Value Run(Connection &connection, const std::string &sql, const Value &text, int64_t limit) {
	// Always consume both parameters, even when a chosen option value is a literal.
	auto result = connection.Query("WITH input AS (SELECT $1::VARCHAR AS text, $2::BIGINT AS n) " + sql, text, limit);
	return Decision(*result);
}

static bool GatekeeperDenial(const ErrorData &error) {
	return error.Type() == ExceptionType::PERMISSION &&
	       error.RawMessage().find("Gatekeeper denied this statement") != std::string::npos;
}

// Names the failing check in the crash log; an unsymbolized libFuzzer stack does not.
static void Fail(const char *why) {
	fprintf(stderr, "gatekeeper fuzz: %s\n", why);
	std::abort();
}

// Whether the text is one PRAGMA statement, which DuckDB rewrites into a SELECT before any hook runs: the
// enforced path then decides that SELECT, while gatekeeper_validate reports the raw text as unsupported.
static bool IsSinglePragma(Connection &connection, const std::string &bytes) {
	try {
		Parser parser(connection.context->GetParserOptions());
		parser.ParseQuery(bytes);
		return parser.statements.size() == 1 && parser.statements[0]->type == StatementType::PRAGMA_STATEMENT;
	} catch (const Exception &error) {
		CheckError(ErrorData(error).Type());
		std::abort(); // validate parsed this text; the engine's parser must too
	}
}

// Under gatekeeper_log_only the same text on a fresh enforced connection must never surface a Gatekeeper
// denial, and the one record it leaves must say what gatekeeper_validate said. The engine then plans the
// statement itself, so DuckDB's own errors for it are permitted; a decision that was refused above is
// exactly what must not be refused here.
static void CheckLogOnlyParity(DuckDB &database, Connection &connection, const std::string &bytes, bool allowed,
                               const string &code, bool pragma_rewrite) {
	if (connection.Query("SET gatekeeper_log_only = true")->HasError())
		Fail("log-only: cannot set the switch");
	Connection observed(database);
	if (observed.Query("CALL gatekeeper_enforce()")->HasError())
		Fail("log-only: cannot enforce the observed connection");
	if (connection.Query("CALL truncate_duckdb_logs()")->HasError())
		Fail("log-only: cannot truncate the log");
	// Zero records are legitimate only when the engine rejects the text before any hook runs: its parser, the
	// PRAGMA and PIVOT preprocessing that runs inside parsing, or the one-statement check PendingQuery applies.
	// The host connection runs that same pipeline here; it is unenforced, so nothing it does is recorded.
	bool before_hooks = false;
	try {
		before_hooks = connection.ExtractStatements(bytes).size() != 1;
	} catch (const std::exception &error) {
		CheckError(ErrorData(error).Type());
		before_hooks = true;
	}
	auto pending = observed.PendingQuery(bytes);
	std::string engine_error; // DuckDB's own rejection of the text, if any
	if (pending->HasError()) {
		CheckError(pending->GetErrorObject().Type());
		if (GatekeeperDenial(pending->GetErrorObject()))
			Fail("log-only: a Gatekeeper denial escaped");
		engine_error = pending->GetErrorObject().RawMessage();
	}
	pending.reset();
	// Query() without parameters materializes; the code is one of Gatekeeper's fixed identifiers.
	std::string same = "allowed = " + std::string(allowed ? "true" : "false") + " AND code = '" + code + "'";
	std::string from = " FROM duckdb_logs_parsed('Gatekeeper') WHERE event = 'decision' AND mode = 'log_only'";
	auto records =
	    connection.Query("SELECT count(*), bool_and(" + same + "), any_value(code), any_value(error_message)" + from);
	if (records->HasError())
		Fail("log-only: cannot read the records");
	auto count = records->GetValue(0, 0).GetValue<int64_t>();
	// The engine's parser may reject text before any hook runs (no record); the preprocessor may rewrite a
	// PRAGMA into a SELECT (a record on that SELECT, which follows the policy rather than the raw text). A dynamic
	// PIVOT is rewritten into several statements, which PendingQuery refuses as a batch before any hook runs.
	if (pragma_rewrite) {
		if (connection.Query("SET gatekeeper_log_only = false")->HasError())
			Fail("log-only: cannot reset the switch");
		return;
	}
	if (count == 0 && !before_hooks)
		Fail("log-only: a statement that reached QueryBegin left no record");
	if (count == 1 && !records->GetValue(1, 0).GetValue<bool>()) {
		// The one other truthful record: the engine rejected the statement on its own (a parameter the caller
		// did not supply, checked before planning on some entry points and after it on others), and the
		// record says exactly that, in the engine's words. gatekeeper_validate binds without values and may
		// have allowed the text.
		bool engine_rejection = !engine_error.empty() && records->GetValue(2, 0).GetValue<string>() == "binding" &&
		                        records->GetValue(3, 0).GetValue<string>() == engine_error;
		if (!engine_rejection)
			Fail("log-only: the record disagrees with gatekeeper_validate");
	}
	if (count > 1) {
		// A rewritten batch leaves one record per statement it ran, and gatekeeper_validate decides the batch in
		// that order: it says what the first denied record says, or allowed when every record is.
		auto first = connection.Query("SELECT " + same + from + (allowed ? "" : " AND NOT allowed") +
		                              " ORDER BY timestamp, context_id LIMIT 1");
		if (first->HasError() || !first->GetValue(0, 0).GetValue<bool>())
			Fail("log-only: the deciding record of a rewritten batch disagrees with gatekeeper_validate");
		if (allowed) {
			auto every = connection.Query("SELECT bool_and(" + same + ")" + from);
			if (every->HasError() || !every->GetValue(0, 0).GetValue<bool>())
				Fail("log-only: a record of an allowed batch disagrees with gatekeeper_validate");
		}
	}
	if (connection.Query("SET gatekeeper_log_only = false")->HasError())
		Fail("log-only: cannot reset the switch");
}

// An enforced connection must agree with gatekeeper_validate under the same global policy. Plan the
// text on a latched connection: PendingQuery runs the binding boundary, the engine's bind, and the
// execution boundary, then schedules pipeline events. Setup() pins the database to threads=1, so no
// worker exists to run a scheduled task and nothing executes before the pending result is discarded.
// The latched connection lives only for this input: a pending result leaves the connection's query
// open until its next statement, and a static connection torn down in that state at exit() reads
// configuration after thread-local storage is gone.
static void CheckEnforcedParity(DuckDB &database, Connection &connection, const std::string &bytes) {
	Connection enforced(database);
	auto latch = enforced.Query("CALL gatekeeper_enforce()");
	if (latch->HasError())
		Fail("enforced: cannot enforce the connection");
	auto truncated = connection.Query("CALL truncate_duckdb_logs()");
	if (truncated->HasError())
		Fail("enforced: cannot truncate the log");
	auto expected = connection.Query("SELECT allowed, code, violations FROM gatekeeper_validate($1)", Value(bytes));
	if (expected->HasError()) {
		CheckError(expected->GetErrorObject().Type());
		return;
	}
	auto chunk = expected->Fetch();
	if (!chunk || chunk->size() != 1)
		Fail("enforced: gatekeeper_validate returned no row");
	auto allowed = chunk->GetValue(0, 0).GetValue<bool>();
	auto code = chunk->GetValue(1, 0).GetValue<string>();
	// Keep the list Value alive for as long as its children are referenced.
	auto violations = chunk->GetValue(2, 0);
	const auto &entries = ListValue::GetChildren(violations);
	bool limit_only = !entries.empty();
	for (const auto &violation : entries)
		if (StructValue::GetChildren(violation)[0].GetValue<string>() != "limit")
			limit_only = false;
	auto pending = enforced.PendingQuery(bytes);
	bool denial = pending->HasError() && GatekeeperDenial(pending->GetErrorObject());
	if (pending->HasError())
		CheckError(pending->GetErrorObject().Type());
	// Validate allowed it: enforcement must not deny it.
	if (allowed && denial)
		Fail("enforced: validate allowed the text but enforcement denied it");
	// Validate forbade it on policy grounds: the engine must not have planned it. The statement-count
	// limit is the one forbidden case the engine rejects itself, before any hook.
	if (code == "forbidden" && !limit_only && !pending->HasError())
		Fail("enforced: validate forbade the text but the engine planned it");
	// Unsupported statement types must not plan either, except pragmas DuckDB rewrites into SELECTs
	// before Gatekeeper sees them, which then follow the policy on that SELECT.
	bool pragma_rewrite = code == "unsupported" && IsSinglePragma(connection, bytes);
	if (code == "unsupported" && !pending->HasError() && !pragma_rewrite)
		Fail("enforced: an unsupported statement was planned");
	pending.reset();
	// Every record written for this input, whatever the text contained, must parse back into the log type.
	auto parsed = connection.Query("SELECT count(*) FROM duckdb_logs_parsed('Gatekeeper')");
	if (parsed->HasError())
		Fail("enforced: a record does not parse back into the log type");
	CheckLogOnlyParity(database, connection, bytes, allowed, code, pragma_rewrite);
}

// Deterministic latch checks, once per process.
static void CheckEnforcedLatch(DuckDB &database) {
	Connection host(database);
	Connection enforced(database);
	auto latch = enforced.Query("CALL gatekeeper_enforce()");
	if (latch->HasError())
		std::abort();
	auto denied = enforced.Query("CREATE TABLE fuzz_denied(x INTEGER)");
	if (!denied->HasError() || !GatekeeperDenial(denied->GetErrorObject()))
		std::abort();
	// The denial is a record the host can read and the sandboxed connection cannot.
	auto recorded = host.Query("SELECT count(*) FROM duckdb_logs_parsed('Gatekeeper') WHERE event = 'decision' AND "
	                           "NOT allowed AND statement = 'CREATE TABLE fuzz_denied(x INTEGER)'");
	if (recorded->HasError() || recorded->GetValue(0, 0).GetValue<int64_t>() != 1)
		std::abort();
	auto unreadable = enforced.Query("SELECT count(*) FROM duckdb_logs");
	if (!unreadable->HasError() || !GatekeeperDenial(unreadable->GetErrorObject()))
		std::abort();
	auto allowed = enforced.Query("SELECT count(*) FROM t");
	if (allowed->HasError())
		std::abort();
	auto relatch = enforced.Query("CALL gatekeeper_enforce()");
	if (!relatch->HasError() || !GatekeeperDenial(relatch->GetErrorObject()))
		std::abort();
	// Log-only: the same statement runs, is recorded as mode log_only, and the flip applies at the next statement.
	if (host.Query("SET gatekeeper_log_only = true")->HasError())
		std::abort();
	auto observed = enforced.Query("CREATE TABLE fuzz_observed(x INTEGER)");
	if (observed->HasError())
		std::abort();
	auto logged =
	    host.Query("SELECT count(*) FROM duckdb_logs_parsed('Gatekeeper') WHERE event = 'decision' AND "
		           "mode = 'log_only' AND NOT allowed AND statement = 'CREATE TABLE fuzz_observed(x INTEGER)'");
	if (logged->HasError() || logged->GetValue(0, 0).GetValue<int64_t>() != 1)
		std::abort();
	if (host.Query("SET gatekeeper_log_only = false")->HasError())
		std::abort();
	auto refused = enforced.Query("DROP TABLE fuzz_observed");
	if (!refused->HasError() || !GatekeeperDenial(refused->GetErrorObject()))
		std::abort();
}

// Every canonical policy value must be NULL-free at every depth.
static void CheckNullFree(const Value &value) {
	if (value.IsNull())
		std::abort();
	if (value.type().id() == LogicalTypeId::STRUCT)
		for (const auto &child : StructValue::GetChildren(value))
			CheckNullFree(child);
	if (value.type().id() == LogicalTypeId::LIST)
		for (const auto &child : ListValue::GetChildren(value))
			CheckNullFree(child);
}

static Value Configured(const std::string &options, const Value &text, int64_t limit) {
	// Configuration is shared by connections: isolate each replay in a fresh instance.
	DuckDB database(nullptr);
	Connection connection(database);
	Setup(connection);
	// The VALUES clause consumes both host parameters even when the option is literal.
	auto result = connection.Query("SELECT cfg.* FROM gatekeeper_configure(" + options +
	                                   ") cfg CROSS JOIN (VALUES ($1::VARCHAR, $2::BIGINT)) input(text,n)",
	                               text, limit);
	Value configured;
	if (result->HasError()) {
		CheckError(result->GetErrorObject().Type());
		configured = Value(result->GetErrorObject().RawMessage());
	} else {
		auto chunk = result->Fetch();
		if (!chunk || chunk->size() != 1)
			std::abort();
		configured = chunk->GetValue(0, 0);
		if (configured.IsNull() || !configured.GetValue<bool>())
			std::abort();
	}
	auto published = connection.Query("SELECT current_setting('gatekeeper_policy')");
	if (published->HasError())
		std::abort();
	CheckNullFree(published->GetValue(0, 0));
	auto decision = Run(connection, "SELECT * FROM gatekeeper_validate('SELECT * FROM v')", text, limit);
	auto overridden =
	    Run(connection, "SELECT * FROM gatekeeper_validate('SELECT md5(''x'')', blocked_functions := [])", text, limit);
	auto baseline = Run(connection, "SELECT * FROM gatekeeper_validate('SELECT md5(''x'')')", text, limit);
	if (!StructValue::GetChildren(baseline)[0].GetValue<bool>() &&
	    StructValue::GetChildren(overridden)[0].GetValue<bool>())
		std::abort();
	return Value::STRUCT({{"configured", configured}, {"decision", decision}, {"overridden", overridden}});
}

static void CheckNativeSettingBypass() {
	DuckDB database(nullptr);
	Connection connection(database);
	Setup(connection);
	auto &config = DBConfig::GetConfig(*database.instance);
	// Native host APIs skip SQL SET callbacks. Only a BOOLEAN true written to gatekeeper_log_only suspends
	// refusals; anything else an enforced connection reads as enforcing.
	{
		Connection enforced(database);
		if (enforced.Query("CALL gatekeeper_enforce()")->HasError())
			std::abort();
		for (const auto &value : {Value("true"), Value(LogicalType::BOOLEAN), Value::INTEGER(1), Value("yes")}) {
			config.SetOption("gatekeeper_log_only", value);
			auto refused = enforced.Query("CREATE TABLE fuzz_native(x INTEGER)");
			if (!refused->HasError() || !GatekeeperDenial(refused->GetErrorObject()))
				std::abort();
		}
		config.SetOption("gatekeeper_log_only", Value::BOOLEAN(true));
		if (enforced.Query("CREATE TABLE fuzz_native(x INTEGER)")->HasError())
			std::abort();
		config.SetOption("gatekeeper_log_only", Value::BOOLEAN(false));
		auto refused = enforced.Query("DROP TABLE fuzz_native");
		if (!refused->HasError() || !GatekeeperDenial(refused->GetErrorObject()))
			std::abort();
	}
	// Enforcement must decode the actual policy value.
	config.SetOption("gatekeeper_policy", Value("invalid"));
	auto invalid = connection.Query("SELECT * FROM gatekeeper_validate('SELECT 1')");
	auto decision = Decision(*invalid);
	if (StructValue::GetChildren(decision)[1].GetValue<string>() != "invalid_input")
		std::abort();
	if (connection.Query("RESET gatekeeper_policy")->HasError())
		std::abort();
	// A deny-only canonical setting must remain effective without restrict_tables.
	auto blocked = connection.Query("SELECT struct_update(current_setting('gatekeeper_policy'), blocked_tables := "
	                                "[{catalog: '', schema: 'main', \"table\": 'v'}])");
	if (blocked->HasError())
		std::abort();
	config.SetOption("gatekeeper_policy", blocked->GetValue(0, 0));
	auto blocked_view = connection.Query("SELECT * FROM gatekeeper_validate('SELECT * FROM v', blocked_tables := [])");
	if (StructValue::GetChildren(Decision(*blocked_view))[1].GetValue<string>() != "forbidden")
		std::abort();
	if (connection.Query("RESET gatekeeper_policy")->HasError())
		std::abort();
	auto canonical =
	    connection.Query("SELECT struct_update(current_setting('gatekeeper_policy'), blocked_functions := ['md5'])");
	if (canonical->HasError())
		std::abort();
	config.SetOption("gatekeeper_policy", canonical->GetValue(0, 0));
	auto denied = connection.Query("SELECT * FROM gatekeeper_validate('SELECT md5(''x'')', blocked_functions := [])");
	if (StructValue::GetChildren(Decision(*denied))[1].GetValue<string>() != "forbidden")
		std::abort();
	// Native setters must not install an ignored nonempty table restriction.
	auto inconsistent =
	    connection.Query("SELECT struct_update(current_setting('gatekeeper_policy'), allowed_tables := "
		                 "[{catalog: 'memory', schema: 'main', \"table\": 'v'}], restrict_tables := false)");
	if (inconsistent->HasError())
		std::abort();
	config.SetOption("gatekeeper_policy", inconsistent->GetValue(0, 0));
	auto ignored = connection.Query("SELECT * FROM gatekeeper_validate('SELECT * FROM secret.t')");
	if (StructValue::GetChildren(Decision(*ignored))[1].GetValue<string>() != "invalid_input")
		std::abort();
	if (connection.Query("RESET gatekeeper_policy")->HasError())
		std::abort();
	// The canonical value is NULL-free at every depth, so a NULL nested catalog installed through a native
	// setter (or DuckDB's lossy STRUCT cast) must fail closed instead of matching any catalog.
	auto widened = connection.Query("SELECT struct_update(current_setting('gatekeeper_policy'), allowed_tables := "
	                                "[{catalog: NULL, schema: 'main', \"table\": 'v'}]::STRUCT(catalog VARCHAR, "
	                                "schema VARCHAR, \"table\" VARCHAR)[])");
	if (widened->HasError())
		std::abort();
	config.SetOption("gatekeeper_policy", widened->GetValue(0, 0));
	auto closed = connection.Query("SELECT * FROM gatekeeper_validate('SELECT * FROM v')");
	if (StructValue::GetChildren(Decision(*closed))[1].GetValue<string>() != "invalid_input")
		std::abort();
	if (connection.Query("RESET gatekeeper_policy")->HasError())
		std::abort();
}

// Host replacement callbacks must only ever run behind Gatekeeper's authorization while validating.
struct ProbeData : ReplacementScanData {
	int calls = 0;
	Connection *other = nullptr; // a second connection used for a nested validation
};

static unique_ptr<TableRef> Reader(const char *function, Value argument) {
	vector<unique_ptr<ParsedExpression>> children;
	children.push_back(make_uniq<ConstantExpression>(std::move(argument)));
	auto ref = make_uniq<TableFunctionRef>();
	ref->function = make_uniq<FunctionExpression>(function, std::move(children));
	return std::move(ref);
}

static unique_ptr<TableRef> ProbeCallback(ClientContext &, ReplacementScanInput &input,
                                          optional_ptr<ReplacementScanData> data) {
	auto &probe = data->Cast<ProbeData>();
	probe.calls++;
	// Declines on its first call and claims on its second: a second engine-driven pass would bypass us.
	if (input.table_name == "second_claim")
		return probe.calls % 2 == 0 ? Reader("read_csv_auto", Value("/gatekeeper/missing/second.csv")) : nullptr;
	// Validates on another connection mid-bind, then yields an admitted reader.
	if (input.table_name == "nested_probe") {
		auto nested = probe.other->Query("SELECT * FROM gatekeeper_validate('SELECT 1')");
		if (nested->HasError() || !StructValue::GetChildren(Decision(*nested))[0].GetValue<bool>())
			std::abort();
		return Reader("range", Value::BIGINT(1));
	}
	if (input.table_name == "denied_probe")
		return Reader("read_csv_auto", Value("/gatekeeper/missing/denied.csv"));
	// A reader that binds without external access, so a view over this name can be created and read.
	if (input.table_name == "trusted_probe")
		return Reader("range", Value::BIGINT(1));
	return nullptr;
}

static std::string Code(Connection &connection, const std::string &sql) {
	auto result = connection.Query("SELECT * FROM gatekeeper_validate($1)", Value(sql));
	if (result->HasError())
		std::abort();
	return StructValue::GetChildren(Decision(*result))[1].GetValue<string>();
}

// The same decision under a request layer that admits no reader: defaults off and the inherited global
// allowed_functions (range, above) overridden, so only the deny layer can pass a replacement.
static std::string StrictCode(Connection &connection, const std::string &sql, const char *blocked = nullptr) {
	auto options = std::string(", use_default_functions := false, allowed_functions := ['count']") +
	               (blocked ? std::string(", blocked_functions := ['") + blocked + "']" : "");
	auto result = connection.Query("SELECT * FROM gatekeeper_validate($1" + options + ")", Value(sql));
	if (result->HasError())
		std::abort();
	return StructValue::GetChildren(Decision(*result))[1].GetValue<string>();
}

static void CheckReplacementCallbacks() {
	DuckDB database(nullptr);
	Connection connection(database), other(database);
	Setup(connection);
	auto &config = DBConfig::GetConfig(*database.instance);
	auto data = make_uniq<ProbeData>();
	auto &probe = *data;
	probe.other = &other;
	config.replacement_scans.emplace_back(ProbeCallback, std::move(data));
	if (connection.Query("CALL gatekeeper_configure(allowed_functions := ['range'])")->HasError())
		std::abort();
	// A stateful callback cannot be reached a second time outside authorization.
	probe.calls = 0;
	if (Code(connection, "SELECT * FROM second_claim") != "binding" || probe.calls != 1)
		std::abort();
	if (Code(connection, "SELECT * FROM second_claim") != "forbidden" || probe.calls != 2)
		std::abort();
	// A nested validation on another connection must not disable interception for the outer bind.
	if (Code(connection, "SELECT * FROM denied_probe") != "forbidden")
		std::abort();
	if (Code(connection, "SELECT * FROM nested_probe CROSS JOIN denied_probe") != "forbidden")
		std::abort();
	// Ordinary queries on the same thread still reach the callback normally.
	probe.calls = 0;
	auto plain = connection.Query("SELECT * FROM nested_probe");
	if (plain->HasError() || probe.calls != 1)
		std::abort();
	// A genuinely missing table keeps the engine's error and invokes the callback exactly once.
	probe.calls = 0;
	if (Code(connection, "SELECT * FROM missing_table") != "binding" || probe.calls != 1)
		std::abort();
	// A replacement reached only through a trusted view body is that view's reader, outside function policy;
	// the same name in the caller's text is the caller's reader choice and must pass the allowlist, also when
	// it stands next to the view. A block on the reader reaches the caller's, not the view's. The view binds on
	// the unenforced connection, where the gate is open.
	if (connection.Query("CREATE VIEW probe_view AS SELECT * FROM trusted_probe")->HasError())
		std::abort();
	if (StrictCode(connection, "SELECT * FROM probe_view") != "ok")
		Fail("trusted probe: the view's replacement reader was held to the allowlist");
	if (StrictCode(connection, "SELECT * FROM trusted_probe") != "forbidden")
		Fail("trusted probe: the caller's replacement reader escaped the allowlist");
	if (StrictCode(connection, "SELECT * FROM probe_view, trusted_probe") != "forbidden")
		Fail("trusted probe: a caller-written name borrowed the view's exemption");
	if (StrictCode(connection, "SELECT * FROM probe_view", "range") != "ok")
		Fail("trusted probe: a block reached the view's replacement reader");
	if (Code(connection, "SELECT * FROM probe_view, trusted_probe") != "ok")
		Fail("trusted probe: the admitted caller reader next to the view was refused");
	if (connection.Query("CALL gatekeeper_configure(allowed_functions := ['range'], blocked_functions := ['range'])")
	        ->HasError())
		std::abort();
	if (Code(connection, "SELECT * FROM probe_view") != "ok")
		Fail("trusted probe: a global block reached the view's replacement reader");
	if (Code(connection, "SELECT * FROM trusted_probe") != "forbidden")
		Fail("trusted probe: a global block did not reach the caller's replacement reader");
	if (connection.Query("CALL gatekeeper_configure(allowed_functions := ['range'])")->HasError())
		std::abort();
	if (connection.Query("DROP VIEW probe_view")->HasError())
		std::abort();
	// Log-only, a parameterized statement reaches the gate on the engine's bind before any private
	// authorization. The gate records the denied reader and hands back the replacement the callback already
	// produced, so the callback runs once for that bind; the reader then fails to bind (external access is off),
	// which is the engine's error and, the statement being decided, no second record.
	if (connection.Query("SET gatekeeper_log_only = true")->HasError())
		std::abort();
	Connection observed(database);
	if (observed.Query("CALL gatekeeper_enforce()")->HasError())
		std::abort();
	probe.calls = 0;
	vector<Value> values{Value::INTEGER(1)};
	auto pending = observed.PendingQuery("SELECT * FROM denied_probe WHERE 1 = $1", values);
	if (!pending->HasError())
		Fail("log-only probe: the missing reader bound");
	if (GatekeeperDenial(pending->GetErrorObject()))
		Fail("log-only probe: a Gatekeeper denial escaped");
	if (probe.calls != 1) {
		fprintf(stderr, "probe calls: %d; error: %s\n", probe.calls, pending->GetErrorObject().RawMessage().c_str());
		Fail("log-only probe: the callback did not run exactly once");
	}
	pending.reset();
	auto recorded = connection.Query("SELECT count(*), any_value(boundary), any_value(code) FROM "
	                                 "duckdb_logs_parsed('Gatekeeper') WHERE event = 'decision' AND mode = 'log_only'");
	if (recorded->HasError() || recorded->GetValue(0, 0).GetValue<int64_t>() != 1 ||
	    recorded->GetValue(1, 0).GetValue<string>() != "replacement_scan" ||
	    recorded->GetValue(2, 0).GetValue<string>() != "forbidden") {
		fprintf(stderr, "%s\n", recorded->ToString().c_str());
		Fail("log-only probe: expected one replacement_scan/forbidden record");
	}
	if (connection.Query("SET gatekeeper_log_only = false")->HasError())
		std::abort();
}

static void CheckFuzzLimits(Connection &connection) {
	for (const auto &limits : {gatekeeper::Limits{7, 100000, 512}, gatekeeper::Limits{8, 100000, 512},
	                           gatekeeper::Limits{8388608, 1, 512}, gatekeeper::Limits{8388608, 100000, 1}}) {
		auto value = GatekeeperCheckForFuzz(*connection.context, "SELECT 1", limits);
		auto &fields = StructValue::GetChildren(value);
		if (fields[0].GetValue<bool>() || fields[1].GetValue<string>() != "forbidden" ||
		    StructValue::GetChildren(ListValue::GetChildren(fields[2]).at(0))[0].GetValue<string>() != "limit")
			std::abort();
	}
	// The internal fuzz hook cannot change the limits used by the SQL entry point.
	if (Code(connection, "SELECT 1") != "ok")
		std::abort();
}

static void CheckForeignAggregateProvenance() {
	struct ProbeBindData : FunctionData {
		unique_ptr<FunctionData> Copy() const override { return make_uniq<ProbeBindData>(); }
		bool Equals(const FunctionData &) const override { return true; }
	};
	for (const auto *name : {"aggregate", "array_aggr", "array_aggregate", "list_aggr", "list_aggregate",
	                         "list_distinct", "list_unique", "array_distinct", "array_unique"}) {
		for (const auto &identity : {std::pair<string, string>{"memory", "main"}, {"system", "custom"}, {"", ""}}) {
			for (bool null_input : {false, true}) {
				ScalarFunction function(name, {LogicalType::INTEGER}, LogicalType::INTEGER, nullptr);
				function.catalog_name = identity.first;
				function.schema_name = identity.second;
				function.SetSerializeCallback([](Serializer &, optional_ptr<FunctionData>, const ScalarFunction &) {
					std::abort(); // A foreign callback must never be invoked, including for NULL inputs.
				});
				vector<unique_ptr<Expression>> children;
				children.push_back(make_uniq<BoundConstantExpression>(null_input ? Value() : Value::INTEGER(1)));
				vector<unique_ptr<Expression>> expressions;
				expressions.push_back(make_uniq<BoundFunctionExpression>(
				    LogicalType::INTEGER, std::move(function), std::move(children), make_uniq<ProbeBindData>()));
				LogicalProjection plan(0, std::move(expressions));
				gatekeeper::Result result;
				try {
					AuthorizePlan(gatekeeper::Policy(), gatekeeper::BindingPolicy(), gatekeeper::Provenance(), plan,
					              result);
					std::abort();
				} catch (const BinderException &error) {
					if (ErrorData(error).RawMessage().find("not the pinned builtin") == string::npos)
						std::abort();
				}
			}
		}
	}
}

static int Fuzz(const uint8_t *data, size_t size) {
	if (size < 4 || size > 4096)
		return 0;
	static DuckDB database(nullptr);
	static Connection connection(database);
	static bool initialized = false;
	if (!initialized) {
		CheckForeignAggregateProvenance();
		for (bool option : {false, true}) {
			auto type = option ? LogicalType::LIST(LogicalType::VARCHAR) : LogicalType::VARCHAR;
			Value null(type);
			auto value = option ? Value::LIST(LogicalType::VARCHAR, {Value("md5")}) : Value("SELECT 1");
			auto different = option ? Value::LIST(LogicalType::VARCHAR, {Value("abs")}) : Value("SELECT 2");
			if (!GatekeeperBindingsEqualForFuzz(null, null, option) ||
			    !GatekeeperBindingsEqualForFuzz(value, value, option) ||
			    GatekeeperBindingsEqualForFuzz(null, value, option) ||
			    GatekeeperBindingsEqualForFuzz(value, null, option) ||
			    GatekeeperBindingsEqualForFuzz(value, different, option))
				std::abort();
		}
		CheckNativeSettingBypass();
		CheckReplacementCallbacks();
		Setup(connection);
		CheckFuzzLimits(connection);
		CheckEnforcedLatch(database);
		auto allow = connection.Query("SELECT allowed FROM gatekeeper_validate('SELECT 1')");
		auto deny =
		    connection.Query("SELECT allowed FROM gatekeeper_validate('SELECT * FROM secret.t', allowed_tables := [])");
		if (allow->HasError() || deny->HasError() || !allow->GetValue(0, 0).GetValue<bool>() ||
		    deny->GetValue(0, 0).GetValue<bool>())
			std::abort();
		initialized = true;
	}
	std::string bytes(reinterpret_cast<const char *>(data + 4), size - 4);
	Value text(bytes);
	// Valid combinations reach all policy layers instead of spending the entire run on type errors.
	if (data[0] % 16 == 13) {
		auto options = string("use_default_functions := ") + (data[1] & 1 ? "true" : "false") +
		               ", allowed_functions := ['sum','list_sum','unnest','list_value','list_transform'], "
		               "blocked_functions := " +
		               (data[1] & 2 ? "['sum','lower','unnest']" : "[]") +
		               ", allowed_tables := " + (data[1] & 4 ? "[]" : "[{schema:'main', 'table':'*'}]") +
		               ", blocked_tables := " + (data[1] & 8 ? "[{schema:'main', 'table':'t'}]" : "[]");
		auto query = "SELECT * FROM gatekeeper_validate($1, " + options + ")";
		if (Run(connection, query, text, data[3]) != Run(connection, query, text, data[3]))
			std::abort();
		return 0;
	}
	// Exercise the production parser/serializer/walker with small internal budgets,
	// without registering SQL options or mutating limits for other validations.
	if (data[0] % 4 == 0) {
		gatekeeper::Limits limits;
		limits.bytes = data[1] ? data[1] * 32 : gatekeeper::MAX_AST_BYTES;
		limits.nodes = data[2] ? data[2] : gatekeeper::MAX_AST_NODES;
		limits.depth = data[3] ? data[3] : gatekeeper::MAX_AST_DEPTH;
		if (GatekeeperCheckForFuzz(*connection.context, bytes, limits) !=
		    GatekeeperCheckForFuzz(*connection.context, bytes, limits))
			std::abort();
	}
	const int64_t limit = data[3];
	auto options = Option(data[1], bytes) + " := " + Argument(data[2]);
	if (data[0] & 128)
		options += ", " + Option(data[1], bytes) + " := NULL"; // Duplicate names.
	else if (data[0] & 64)
		options += ", " + Option(data[1] + 1, bytes) + " := " + Argument(data[3]);
	if (data[0] % 16 == 15) {
		if (Configured(options, text, limit) != Configured(options, text, limit))
			std::abort();
		return 0;
	}
	if (data[0] % 16 == 12) {
		CheckEnforcedParity(database, connection, bytes);
		return 0;
	}
	if (data[0] % 16 == 14) {
		// A resolved function denial must also reject its explicit caller spelling.
		auto first = Run(
		    connection, "SELECT * FROM gatekeeper_validate($1, blocked_functions := ['json_extract','struct_extract'])",
		    text, limit);
		if (StructValue::GetChildren(first).size() == 8) {
			for (const auto &violation : ListValue::GetChildren(StructValue::GetChildren(first)[2])) {
				auto &fields = StructValue::GetChildren(violation);
				if (fields[0].GetValue<string>() != "function")
					continue;
				auto name = fields[5].GetValue<string>();
				std::string quoted;
				for (auto c : name) {
					if (c == '"')
						quoted += '"';
					quoted += c;
				}
				auto explicit_result =
				    Run(connection,
					    "SELECT * FROM gatekeeper_validate($1, blocked_functions := ['json_extract','struct_extract'])",
					    Value("SELECT \"" + quoted + "\"(1)"), limit);
				auto &decision = StructValue::GetChildren(explicit_result);
				if (decision.size() != 8 || decision[1].GetValue<string>() != "forbidden")
					std::abort();
			}
		}
		return 0;
	}
	std::string sql;
	if (data[0] % 4 == 0) {
		sql = "SELECT * FROM gatekeeper_validate($1)";
	} else {
		sql = "SELECT * FROM gatekeeper_validate(" + std::string(data[0] % 4 == 1 ? "'SELECT * FROM t'" : "$1") + ", " +
		      options + ")";
	}
	if (Run(connection, sql, text, limit) != Run(connection, sql, text, limit))
		std::abort();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	try {
		return Fuzz(data, size);
	} catch (const Exception &error) {
		CheckError(ErrorData(error).Type());
		// Invalid byte sequences can fail before Query() constructs its result.
		return 0;
	}
}
