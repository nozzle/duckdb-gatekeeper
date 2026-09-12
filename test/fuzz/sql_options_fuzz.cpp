#include "duckdb.hpp"
#include <cstdlib>
#include <string>

static int Fuzz(const uint8_t *data, size_t size) {
	if (size < 1 || size > 4096)
		return 0;
	static duckdb::DuckDB database(nullptr);
	static duckdb::Connection connection(database);
	static bool initialized = false;
	if (!initialized) {
		auto result = connection.Query("SET enable_external_access=false; SET autoload_known_extensions=false; SET "
		                               "autoinstall_known_extensions=false; CREATE TABLE t(x INTEGER); CREATE SCHEMA "
		                               "secret; CREATE TABLE secret.t(x "
		                               "INTEGER); CREATE VIEW v AS SELECT * FROM t");
		if (result->HasError())
			std::abort();
		auto check = connection.Query("SELECT gatekeeper_validate('SELECT 1').allowed");
		if (check->HasError() || !check->GetValue(0, 0).GetValue<bool>())
			std::abort();
		auto deny =
		    connection.Query("SELECT gatekeeper_validate('SELECT * FROM secret.t', allowed_tables := []).allowed");
		if (deny->HasError() || deny->GetValue(0, 0).GetValue<bool>())
			std::abort();
		initialized = true;
	}
	duckdb::Value text(std::string(reinterpret_cast<const char *>(data + 1), size - 1));
	duckdb::unique_ptr<duckdb::QueryResult> result;
	if (data[0] % 5 == 0) {
		result = connection.Query(
		    "SELECT gatekeeper_validate($1, blocked_functions := ['read_parquet','query','gatekeeper_configure'], "
		    "max_ast_bytes := 65536, max_ast_nodes := 2000, max_ast_depth := 100)",
		    text);
	} else if (data[0] % 5 == 1) {
		result = connection.Query(
		    "SELECT gatekeeper_validate('SELECT sum(x) FROM t', allowed_schemas := [$1], max_ast_depth := $2)", text,
		    int64_t(data[0]));
	} else if (data[0] % 5 == 2) {
		result = connection.Query(
		    "SELECT gatekeeper_validate('SELECT md5(''x'')', blocked_functions := [$1], check_functions := $2)", text,
		    bool(data[0] & 1));
	} else if (data[0] % 5 == 3) {
		result = connection.Query(
		    "SELECT gatekeeper_validate('SELECT * FROM t', allowed_tables := [{schema:'main', 'table':$1}])", text);
	} else {
		result = connection.Query("SELECT gatekeeper_validate('SELECT 1', check_functions := $1)", text);
	}
	if (result->HasError())
		return 0;
	auto chunk = result->Fetch();
	if (!chunk || chunk->size() != 1)
		std::abort();
	auto value = chunk->GetValue(0, 0);
	auto &fields = duckdb::StructValue::GetChildren(value);
	if (fields[0].GetValue<bool>() != (fields[1].GetValue<std::string>() == "ok"))
		std::abort();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	try {
		return Fuzz(data, size);
	} catch (const duckdb::Exception &) {
		// Invalid byte sequences may be rejected while constructing C++ parameter values.
		return 0;
	}
}
