#pragma once
#include "duckdb.hpp"
#include "yyjson.hpp"
#include <set>
#include <tuple>
#include <unordered_map>

namespace gatekeeper {
using Json = duckdb_yyjson::yyjson_val;
using Names = std::set<std::string>;
struct Table {
	std::string catalog, schema, table;
	bool operator<(const Table &other) const {
		return std::tie(catalog, schema, table) < std::tie(other.catalog, other.schema, other.table);
	}
};
struct Policy {
	bool functions = true, defaults = true, catalogs = false, schemas = false, tables = false;
	bool recursive = true, table_functions = true, dynamic_sql = false, file_tables = false;
	bool resolve_objects = true;
	bool defer_table_checks = false;
	Names allowed_functions, blocked_functions, allowed_catalogs, allowed_schemas;
	std::set<Table> allowed_tables;
	uint64_t statements = 1, bytes = 8388608, nodes = 100000, depth = 512;
	explicit Policy(Json *value);
	void Apply(Json *value);
};
struct Result {
	bool allowed = false;
	std::string code, error_type, error_message;
	Names violations;
};
std::string Text(Json *value);
std::string Field(Json *value, const char *key);
std::string Lower(std::string value);
Result Validate(Json *root, const Policy &policy);
} // namespace gatekeeper
