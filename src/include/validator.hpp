#pragma once
#include "yyjson.hpp"
#include <cstdint>
#include <set>
#include <string>
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
	Names allowed_functions, blocked_functions, allowed_catalogs, allowed_schemas;
	std::set<Table> allowed_tables;
	uint64_t statements = 1, bytes = 8388608, nodes = 100000, depth = 512;
};
struct Violation {
	std::string rule, message, catalog, schema, table, function_name;
	int64_t position = -1;
	Violation(std::string message) : rule("unsupported_structure"), message(std::move(message)) {}
	Violation(std::string rule, std::string message, std::string catalog = {}, std::string schema = {},
	          std::string table = {}, std::string function_name = {}, int64_t position = -1)
	    : rule(std::move(rule)), message(std::move(message)), catalog(std::move(catalog)), schema(std::move(schema)),
	      table(std::move(table)), function_name(std::move(function_name)), position(position) {}
	bool operator<(const Violation &other) const {
		return std::tie(rule, message, catalog, schema, table, function_name, position) <
		       std::tie(other.rule, other.message, other.catalog, other.schema, other.table, other.function_name,
		                other.position);
	}
};
struct Result {
	bool allowed = false;
	std::string code, error_type, error_message;
	std::set<Violation> violations;
	int64_t position = -1;
};
std::string Text(Json *value);
std::string Field(Json *value, const char *key);
std::string Lower(std::string value);
Result Validate(Json *root, const Policy &policy);
} // namespace gatekeeper
