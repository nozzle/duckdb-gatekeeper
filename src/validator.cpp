#include "validator.hpp"
#include "grammar.hpp"
#include "inventory.hpp"
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#include <vector>

namespace gatekeeper {
using namespace duckdb_yyjson;
using Doc = std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)>;

std::string Text(Json *value) {
	return yyjson_is_str(value) ? std::string(yyjson_get_str(value), yyjson_get_len(value)) : std::string();
}
std::string Field(Json *value, const char *key) { return Text(yyjson_obj_get(value, key)); }
std::string Lower(std::string value) {
	for (auto &c : value)
		if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';
	return value;
}
static void Invalid(const std::string &message) { throw std::invalid_argument(message); }
static Names Strings(Json *value, bool lower = false) {
	if (!yyjson_is_arr(value))
		Invalid("expected string array");
	Names names;
	size_t i, count;
	Json *item;
	yyjson_arr_foreach(value, i, count, item) {
		if (!yyjson_is_str(item) || !yyjson_get_len(item))
			Invalid("expected nonempty string");
		names.insert(lower ? Lower(Text(item)) : Text(item));
	}
	return names;
}

struct Rule {
	std::unordered_map<std::string, std::string> fields;
	Names required;
};
struct Inventory {
	Doc grammar{yyjson_read(grammar_json, strlen(grammar_json), 0), yyjson_doc_free};
	Doc inventory{yyjson_read(inventory_json, strlen(inventory_json), 0), yyjson_doc_free};
	std::unordered_map<std::string, Rule> rules;
	std::unordered_map<std::string, std::unordered_map<std::string, std::string>> dispatch;
	Names defaults;
	const std::unordered_map<std::string, Names> expression_types = {
	    {"BETWEEN", {"COMPARE_BETWEEN", "COMPARE_NOT_BETWEEN"}},
	    {"CASE", {"CASE_EXPR"}},
	    {"CAST", {"OPERATOR_CAST"}},
	    {"COLLATE", {"COLLATE"}},
	    {"COLUMN_REF", {"COLUMN_REF"}},
	    {"COMPARISON",
		 {"COMPARE_EQUAL", "COMPARE_NOTEQUAL", "COMPARE_LESSTHAN", "COMPARE_GREATERTHAN", "COMPARE_LESSTHANOREQUALTO",
		  "COMPARE_GREATERTHANOREQUALTO", "COMPARE_DISTINCT_FROM", "COMPARE_NOT_DISTINCT_FROM"}},
	    {"CONJUNCTION", {"CONJUNCTION_AND", "CONJUNCTION_OR"}},
	    {"CONSTANT", {"VALUE_CONSTANT"}},
	    {"FUNCTION", {"FUNCTION"}},
	    {"LAMBDA", {"LAMBDA"}},
	    {"OPERATOR",
		 {"OPERATOR_NOT", "OPERATOR_IS_NULL", "OPERATOR_IS_NOT_NULL", "OPERATOR_UNPACK", "COMPARE_IN", "COMPARE_NOT_IN",
		  "GROUPING_FUNCTION", "OPERATOR_COALESCE", "ARRAY_EXTRACT", "ARRAY_SLICE", "STRUCT_EXTRACT",
		  "ARRAY_CONSTRUCTOR", "ARROW", "OPERATOR_TRY"}},
	    {"PARAMETER", {"VALUE_PARAMETER"}},
	    {"POSITIONAL_REFERENCE", {"POSITIONAL_REFERENCE"}},
	    {"STAR", {"STAR"}},
	    {"SUBQUERY", {"SUBQUERY"}},
	    {"WINDOW",
		 {"WINDOW_AGGREGATE", "WINDOW_RANK", "WINDOW_RANK_DENSE", "WINDOW_NTILE", "WINDOW_PERCENT_RANK",
		  "WINDOW_CUME_DIST", "WINDOW_ROW_NUMBER", "WINDOW_FIRST_VALUE", "WINDOW_LAST_VALUE", "WINDOW_LEAD",
		  "WINDOW_LAG", "WINDOW_NTH_VALUE", "WINDOW_FILL"}}};
	Inventory() {
		if (!grammar || !inventory)
			throw std::runtime_error("invalid embedded inventory");
		auto root = yyjson_doc_get_root(grammar.get());
		size_t i, n, j, m;
		Json *key, *value, *field, *type;
		yyjson_obj_foreach(yyjson_obj_get(root, "rules"), i, n, key, value) {
			Rule rule;
			yyjson_obj_foreach(yyjson_obj_get(value, "fields"), j, m, field, type)
			    rule.fields.emplace(Text(field), Text(type));
			rule.required = Strings(yyjson_obj_get(value, "required"));
			rules.emplace(Text(key), std::move(rule));
		}
		yyjson_obj_foreach(yyjson_obj_get(root, "dispatch"), i, n, key, value) {
			auto &mapping = dispatch[Text(key)];
			yyjson_obj_foreach(value, j, m, field, type) mapping.emplace(Text(field), Text(type));
		}
		auto data = yyjson_doc_get_root(inventory.get());
		defaults = Strings(yyjson_obj_get(data, "defaults"));
	}
};

static bool FileName(const std::string &name) {
	auto lower = Lower(name);
	if (name.find('/') != std::string::npos || name.find('\\') != std::string::npos ||
	    name.find("://") != std::string::npos)
		return true;
	for (auto suffix : {".parquet", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".gz", ".zst", ".xlsx", ".db", ".ddb",
	                    ".duckdb", ".avro", ".shp", ".gpkg", ".fgb"}) {
		if (lower.size() >= strlen(suffix) && lower.compare(lower.size() - strlen(suffix), strlen(suffix), suffix) == 0)
			return true;
		if (lower.find(std::string(suffix) + "?") != std::string::npos)
			return true;
	}
	return false;
}
struct Stop {
	std::string message;
	std::string rule = "unsupported_structure";
};
struct Walker {
	const Inventory &inventory;
	const Policy &policy;
	std::set<Violation> violations;
	std::map<std::string, size_t> functions;
	std::map<std::string, int64_t> function_positions;
	uint64_t nodes = 0;
	struct Work {
		Json *value;
		std::string expected;
		Names scope;
		size_t depth;
		std::string edge;
	};
	std::vector<Work> pending;
	void Reject(const std::string &rule, const std::string &message, Json *node = nullptr,
	            const std::string &function = {}) {
		auto location = yyjson_obj_get(node, "query_location");
		violations.emplace(rule, message, Field(node, "catalog_name"), Field(node, "schema_name"),
		                   Field(node, "table_name"), function,
		                   yyjson_is_uint(location) ? int64_t(yyjson_get_uint(location)) : -1);
	}
	void References(Json *value, const std::string &kind, const Names &scope, const std::string &edge) {
		if (kind == "FunctionExpression" || kind == "WindowExpression") {
			auto name = Lower(Field(value, "function_name"));
			functions[name]++;
			auto location = yyjson_obj_get(value, "query_location");
			if (yyjson_is_uint(location)) {
				auto position = int64_t(yyjson_get_uint(location));
				auto found = function_positions.find(name);
				if (position >= 0 && (found == function_positions.end() || position < found->second))
					function_positions[name] = position;
			}
			auto catalog = Field(value, "catalog");
			if (policy.catalogs && !catalog.empty() && !policy.allowed_catalogs.count(catalog))
				violations.emplace("catalog", "catalog is not allowed: " + catalog, catalog, Field(value, "schema"), "",
				                   name);
			if (!policy.dynamic_sql && ((edge == "function" && (name == "query" || name == "query_table" ||
			                                                    name == "json_execute_serialized_sql")) ||
			                            name == "json_serialize_plan"))
				Reject("dynamic_sql", "dynamic SQL is disabled: " + name, value, name);
		}
		if (kind == "RecursiveCTENode" && !policy.recursive)
			Reject("recursive_cte", "recursive CTEs are disabled", value);
		if (kind == "TableFunctionRef") {
			if (!policy.table_functions)
				Reject("table_function", "table functions are disabled", value,
				       Field(yyjson_obj_get(value, "function"), "function_name"));
		}
		if (kind != "BaseTableRef" && kind != "ShowRef")
			return;
		auto catalog = Field(value, "catalog_name"), schema = Field(value, "schema_name"),
		     table = Field(value, "table_name");
		if (policy.catalogs && !catalog.empty() && !policy.allowed_catalogs.count(catalog))
			Reject("catalog", "catalog is not allowed: " + catalog, value);
		if (kind == "ShowRef") {
			if (yyjson_obj_get(value, "query"))
				return;
			if (policy.tables)
				Reject("table", "schema-wide SHOW is disabled by table policy", value);
			if (policy.schemas && (schema.empty() || !policy.allowed_schemas.count(schema)))
				Reject("schema", "SHOW requires an allowed schema", value);
			return;
		}
		if (catalog.empty() && schema.empty() && scope.count(Lower(table)))
			return;
		if (!policy.file_tables && FileName(table))
			Reject("file_table", "file table reference is disabled: " + table, value);
	}
	void Check(Json *value, std::string expected, Names scope = {}, size_t depth = 0, std::string edge = {}) {
		pending.push_back({value, std::move(expected), std::move(scope), depth, std::move(edge)});
		while (!pending.empty()) {
			auto work = std::move(pending.back());
			pending.pop_back();
			CheckNode(work.value, std::move(work.expected), std::move(work.scope), work.depth, std::move(work.edge));
		}
	}
	void CheckNode(Json *value, std::string expected, Names scope, size_t depth, std::string edge) {
		if (++nodes > policy.nodes || depth > policy.depth)
			throw Stop{"AST size or depth limit exceeded", "limit"};
		if (expected == "opaque")
			return;
		if (expected.size() > 2 && expected.substr(expected.size() - 2) == "[]") {
			if (!yyjson_is_arr(value))
				throw Stop{"expected array"};
			size_t i, n;
			Json *child;
			yyjson_arr_foreach(value, i, n, child)
			    pending.push_back({child, expected.substr(0, expected.size() - 2), scope, depth + 1, {}});
			return;
		}
		if (expected == "string" || expected == "boolean" || expected == "number") {
			if ((expected == "string" && !yyjson_is_str(value)) || (expected == "boolean" && !yyjson_is_bool(value)) ||
			    (expected == "number" && !yyjson_is_num(value)))
				throw Stop{"unexpected field type"};
			return;
		}
		if (!yyjson_is_obj(value))
			throw Stop{"expected AST object"};
		auto dispatch = inventory.dispatch.find(expected);
		if (dispatch != inventory.dispatch.end()) {
			auto tag = Field(value, expected == "ParsedExpression" ? "class" : "type");
			if (expected == "ParsedExpression") {
				auto types = inventory.expression_types.find(tag);
				if (types == inventory.expression_types.end() || !types->second.count(Field(value, "type")))
					throw Stop{"unsupported expression type"};
			}
			auto found = dispatch->second.find(tag);
			if (found == dispatch->second.end())
				throw Stop{"unsupported AST kind: " + tag};
			expected = found->second;
		}
		auto found = inventory.rules.find(expected);
		if (found == inventory.rules.end())
			throw Stop{"unknown grammar rule"};
		auto &rule = found->second;
		if (expected == "ShowRef" &&
		    !Names{"SHOW_FROM", "SHOW_UNQUALIFIED", "DESCRIBE", "SUMMARY"}.count(Field(value, "show_type")))
			throw Stop{"unsupported SHOW kind"};
		if (expected == "SetOperationNode" &&
		    !Names{"UNION", "EXCEPT", "INTERSECT", "UNION_BY_NAME"}.count(Field(value, "setop_type")))
			throw Stop{"unsupported set operation"};
		for (auto &name : rule.required)
			if (!yyjson_obj_getn(value, name.data(), name.size()))
				throw Stop{"missing AST field: " + name};
		Names seen;
		size_t i, n;
		Json *key, *child;
		yyjson_obj_foreach(value, i, n, key, child) {
			auto name = Text(key);
			if (!seen.insert(name).second || !rule.fields.count(name))
				throw Stop{"unknown AST field: " + name};
		}
		auto ctes = yyjson_obj_get(value, "cte_map");
		if (ctes) {
			if (!yyjson_is_obj(ctes) || yyjson_obj_size(ctes) > 1)
				throw Stop{"invalid CTE map"};
			auto entries = yyjson_obj_get(ctes, "map");
			if ((yyjson_obj_size(ctes) && !entries) || (entries && !yyjson_is_arr(entries)))
				throw Stop{"invalid CTE entries"};
			Names declared;
			yyjson_arr_foreach(entries, i, n, child) {
				pending.push_back({child, "cte_entry", scope, depth + 1, {}});
				auto name = Lower(Field(child, "key"));
				if (!declared.insert(name).second)
					throw Stop{"duplicate CTE"};
				scope.insert(name);
			}
		}
		yyjson_obj_foreach(value, i, n, key, child) {
			auto name = Text(key);
			if (name == "cte_map")
				continue;
			auto next = scope;
			if (expected == "RecursiveCTENode" && name == "right")
				next.insert(Lower(Field(value, "cte_name")));
			pending.push_back({child, rule.fields.at(name), std::move(next), depth + 1, name});
		}
		References(value, expected, scope, edge);
	}
};

Result Validate(Json *root, const Policy &policy) {
	static const Inventory inventory;
	Walker walker{inventory, policy};
	try {
		walker.Check(root, "root");
	} catch (const Stop &error) {
		return {false, error.rule == "limit" ? "forbidden" : "unsupported", "", "", {{error.rule, error.message}}};
	}
	for (auto &entry : walker.functions) {
		auto &name = entry.first;
		bool blocked = policy.blocked_functions.count(name);
		bool allowed = !policy.functions || policy.allowed_functions.count(name) ||
		               (policy.defaults && inventory.defaults.count(name));
		if (blocked || !allowed) {
			auto message = "function is not allowed: " + name;
			if (entry.second > 1)
				message += " (" + std::to_string(entry.second) + " occurrences)";
			auto found = walker.function_positions.find(name);
			walker.violations.emplace("function", message, "", "", "", name,
			                          found == walker.function_positions.end() ? -1 : found->second);
		}
	}
	return {walker.violations.empty(), walker.violations.empty() ? "ok" : "forbidden", "", "", walker.violations};
}
} // namespace gatekeeper
