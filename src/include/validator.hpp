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
// Fixed validation guardrails, independent of authorization policy.
constexpr uint64_t MAX_STATEMENTS = 1;
constexpr uint64_t MAX_AST_BYTES = 8388608;
constexpr uint64_t MAX_AST_NODES = 100000;
constexpr uint64_t MAX_AST_DEPTH = 512;
// Internal injection point for fuzzing; SQL entry points always use these defaults.
struct Limits {
	uint64_t bytes = MAX_AST_BYTES, nodes = MAX_AST_NODES, depth = MAX_AST_DEPTH;
};
struct Table {
	std::string catalog, schema, table;
	bool operator<(const Table &other) const {
		return std::tie(catalog, schema, table) < std::tie(other.catalog, other.schema, other.table);
	}
};
struct Policy {
	bool defaults = true, tables = false;
	Names allowed_functions, blocked_functions;
	std::set<Table> allowed_tables, blocked_tables;
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
struct Identity {
	std::string catalog, schema, name, type;
	bool operator<(const Identity &other) const {
		return std::tie(catalog, schema, name, type) < std::tie(other.catalog, other.schema, other.name, other.type);
	}
};
struct Result {
	bool allowed = false;
	std::string code, error_type, error_message;
	std::set<Violation> violations;
	int64_t position = -1;
	std::set<Identity> objects, functions;
};
struct BindingPolicy {
	// Ambiguous caller syntax: enforce only the implementation actually looked up.
	Names synthesized_functions;
	Names literal_constructors;
	Names runtime_table_functions;
	// Caller-written list_aggregate/aggregate family calls: the aggregate they select by name is caller-chosen
	// text, so the bound implementation must pass the allowlists like any other caller-written function.
	Names caller_dispatchers;
};
std::string Text(Json *value);
std::string Field(Json *value, const char *key);
std::string Lower(std::string value);
bool TableAllowed(const Policy &policy, const std::string &catalog, const std::string &schema, const std::string &table,
                  bool internal = false);
bool TableBlocked(const Policy &policy, const std::string &catalog, const std::string &schema,
                  const std::string &table);
Result Validate(Json *root, const Policy &policy, BindingPolicy *binding = nullptr, const Policy *ceiling = nullptr,
                const Limits &limits = Limits());
} // namespace gatekeeper
