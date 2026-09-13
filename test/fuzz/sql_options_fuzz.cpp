#include "duckdb.hpp"
#include "engine_errors.hpp"
#include <cstdlib>
#include <string>

using namespace duckdb;

static void CheckError(ExceptionType type) {
	if (gatekeeper::PropagateEngineError(type))
		std::abort();
}

static void Setup(Connection &connection) {
	auto result = connection.Query(
	    "SET enable_external_access=false; SET autoload_known_extensions=false; SET "
	    "autoinstall_known_extensions=false; "
	    "SET threads=1; CREATE TABLE t(x INTEGER); CREATE SCHEMA secret; CREATE TABLE secret.t(x INTEGER); "
	    "CREATE VIEW v AS SELECT * FROM t");
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
	auto value = chunk->GetValue(0, 0);
	if (value.IsNull())
		std::abort();
	auto &fields = StructValue::GetChildren(value);
	if (fields.size() != 6)
		std::abort();
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
	static const char *names[] = {"check_functions",       "use_default_functions", "allow_recursive_ctes",
	                              "allow_table_functions", "allow_dynamic_sql",     "allow_file_table_references",
	                              "allowed_functions",     "blocked_functions",     "allowed_catalogs",
	                              "allowed_schemas",       "allowed_tables",        "max_statements",
	                              "max_ast_bytes",         "max_ast_nodes",         "max_ast_depth",
	                              "allowed_types"};
	if (selector % 17 < 16)
		return names[selector % 17];
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
	static const char *values[] = {"$1",
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
	                               "8388609",
	                               "[{schema:'main', type:$1}]",
	                               "[{catalog:'system', schema:'main', type:$1}]",
	                               "[{schema:'main', type:NULL}]",
	                               "[{schema:'main', type:{nested:$1}}]"};
	return values[selector % (sizeof(values) / sizeof(values[0]))];
}

static Value Run(Connection &connection, const std::string &sql, const Value &text, int64_t limit) {
	// Always consume both parameters, even when a chosen option value is a literal.
	auto result = connection.Query("WITH input AS (SELECT $1::VARCHAR AS text, $2::BIGINT AS n) " + sql, text, limit);
	return Decision(*result);
}

static Value Configured(const std::string &options, const Value &text, int64_t limit) {
	// Configuration is one-shot and shared by connections: isolate each replay in a fresh instance.
	DuckDB database(nullptr);
	Connection connection(database);
	Setup(connection);
	auto result = connection.Query("WITH input AS (SELECT $1::VARCHAR AS text, $2::BIGINT AS n) "
	                               "SELECT gatekeeper_configure(" +
	                                   options + ") FROM input",
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
	auto decision = Run(connection, "SELECT gatekeeper_validate('SELECT * FROM v') FROM input", text, limit);
	auto overridden = Run(
	    connection, "SELECT gatekeeper_validate('SELECT md5(''x'')', blocked_functions := []) FROM input", text, limit);
	return Value::STRUCT({{"configured", configured}, {"decision", decision}, {"overridden", overridden}});
}

static int Fuzz(const uint8_t *data, size_t size) {
	if (size < 4 || size > 4096)
		return 0;
	static DuckDB database(nullptr);
	static Connection connection(database);
	static bool initialized = false;
	if (!initialized) {
		Setup(connection);
		auto allow = connection.Query("SELECT gatekeeper_validate('SELECT 1').allowed");
		auto deny =
		    connection.Query("SELECT gatekeeper_validate('SELECT * FROM secret.t', allowed_tables := []).allowed");
		if (allow->HasError() || deny->HasError() || !allow->GetValue(0, 0).GetValue<bool>() ||
		    deny->GetValue(0, 0).GetValue<bool>())
			std::abort();
		initialized = true;
	}
	std::string bytes(reinterpret_cast<const char *>(data + 4), size - 4);
	Value text(bytes);
	const int64_t limit = data[3];
	auto options = Option(data[1], bytes) + " := " + Argument(data[2]);
	if (data[0] & 128)
		options += ", " + Option(data[1], bytes) + " := NULL"; // Duplicate names.
	if (data[0] % 16 == 15) {
		if (Configured(options, text, limit) != Configured(options, text, limit))
			std::abort();
		return 0;
	}
	if (data[0] % 16 == 14) {
		// A resolved function denial must also reject its explicit caller spelling.
		auto first =
		    Run(connection,
			    "SELECT gatekeeper_validate($1, blocked_functions := ['json_extract','struct_extract']) FROM input",
			    text, limit);
		if (StructValue::GetChildren(first).size() == 6) {
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
				auto explicit_result = Run(
				    connection,
				    "SELECT gatekeeper_validate($1, blocked_functions := ['json_extract','struct_extract']) FROM input",
				    Value("SELECT \"" + quoted + "\"(1)"), limit);
				auto &decision = StructValue::GetChildren(explicit_result);
				if (decision.size() != 6 || decision[1].GetValue<string>() != "forbidden")
					std::abort();
			}
		}
		return 0;
	}
	std::string sql;
	if (data[0] % 4 == 0) {
		sql = "SELECT gatekeeper_validate($1, max_ast_bytes := " + std::to_string(data[1] ? data[1] * 32 : 65536) +
		      ", max_ast_nodes := " + std::to_string(data[2] ? data[2] : 2000) +
		      ", max_ast_depth := " + std::to_string(data[3] ? data[3] : 100) +
		      ", max_statements := " + std::to_string(1 + data[1] % 4) + ") FROM input";
	} else {
		sql = "SELECT gatekeeper_validate(" + std::string(data[0] % 4 == 1 ? "'SELECT * FROM t'" : "$1") + ", " +
		      options + ") FROM input";
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
