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
static uint64_t Limit(Json *value, uint64_t ceiling) {
	if (!yyjson_is_uint(value) || !yyjson_get_uint(value) || yyjson_get_uint(value) > ceiling)
		Invalid("invalid limit");
	return yyjson_get_uint(value);
}

Policy::Policy(Json *value) {
	if (value)
		Apply(value);
}

void Policy::Apply(Json *value) {
	if (!yyjson_is_obj(value))
		Invalid("options must be an object");
	Names seen;
	size_t i, count;
	Json *key, *item;
	yyjson_obj_foreach(value, i, count, key, item) {
		auto name = Text(key);
		if (!seen.insert(name).second)
			Invalid("duplicate option: " + name);
		if (name == "check_functions" || name == "use_default_functions" || name == "allow_recursive_ctes" ||
		    name == "allow_table_functions" || name == "allow_dynamic_sql" || name == "allow_file_table_references" ||
		    name == "resolve_objects") {
			if (!yyjson_is_bool(item))
				Invalid("expected boolean: " + name);
			bool flag = yyjson_get_bool(item);
			if (name == "check_functions")
				functions = flag;
			if (name == "use_default_functions")
				defaults = flag;
			if (name == "allow_recursive_ctes")
				recursive = flag;
			if (name == "allow_table_functions")
				table_functions = flag;
			if (name == "allow_dynamic_sql")
				dynamic_sql = flag;
			if (name == "allow_file_table_references")
				file_tables = flag;
			if (name == "resolve_objects")
				resolve_objects = flag;
		} else if (name == "allowed_functions")
			allowed_functions = Strings(item, true);
		else if (name == "blocked_functions")
			blocked_functions = Strings(item, true);
		else if (name == "allowed_catalogs") {
			catalogs = true;
			allowed_catalogs = Strings(item);
		} else if (name == "allowed_schemas") {
			schemas = true;
			allowed_schemas = Strings(item);
		} else if (name == "allowed_tables") {
			tables = true;
			allowed_tables.clear();
			if (!yyjson_is_arr(item))
				Invalid("allowed_tables must be an array");
			size_t j, n;
			Json *entry;
			yyjson_arr_foreach(item, j, n, entry) {
				if (!yyjson_is_obj(entry))
					Invalid("expected table object");
				Names fields;
				size_t k, m;
				Json *field, *text;
				yyjson_obj_foreach(entry, k, m, field, text) {
					auto f = Text(field);
					if (!fields.insert(f).second || (f != "catalog" && f != "schema" && f != "table") ||
					    !yyjson_is_str(text) || !yyjson_get_len(text))
						Invalid("invalid table entry");
				}
				if (!fields.count("schema") || !fields.count("table"))
					Invalid("table entries require schema and table");
				allowed_tables.insert({Field(entry, "catalog"), Field(entry, "schema"), Field(entry, "table")});
			}
		} else if (name == "limits") {
			statements = 1;
			bytes = 8388608;
			nodes = 100000;
			depth = 512;
			if (!yyjson_is_obj(item))
				Invalid("limits must be an object");
			Names fields;
			size_t j, n;
			Json *field, *limit;
			yyjson_obj_foreach(item, j, n, field, limit) {
				auto f = Text(field);
				if (!fields.insert(f).second)
					Invalid("duplicate limit");
				if (f == "max_statements")
					statements = Limit(limit, 1000);
				else if (f == "max_ast_bytes")
					bytes = Limit(limit, 8388608);
				else if (f == "max_ast_nodes")
					nodes = Limit(limit, 100000);
				else if (f == "max_ast_depth")
					depth = Limit(limit, 512);
				else
					Invalid("unknown limit: " + f);
			}
		} else
			Invalid("unknown option: " + name);
	}
	if (seen.count("check_functions") && !seen.count("use_default_functions"))
		defaults = functions;
	if (!functions && !seen.count("allowed_functions"))
		allowed_functions.clear();
	if (!functions && !seen.count("use_default_functions"))
		defaults = false;
	if (!functions && (defaults || !allowed_functions.empty()))
		Invalid("allowlist options require check_functions");
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
	for (auto suffix : {".parquet", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".gz", ".zst", ".xlsx"}) {
		if (lower.size() >= strlen(suffix) && lower.compare(lower.size() - strlen(suffix), strlen(suffix), suffix) == 0)
			return true;
	}
	return false;
}
struct Stop {
	std::string message;
};
struct Walker {
	const Inventory &inventory;
	const Policy &policy;
	Names violations;
	std::map<std::string, size_t> functions;
	uint64_t nodes = 0;
	struct Work {
		Json *value;
		std::string expected;
		Names scope;
		size_t depth;
		std::string edge;
	};
	std::vector<Work> pending;
	void Reject(const std::string &message) { violations.insert(message); }
	void References(Json *value, const std::string &kind, const Names &scope, const std::string &edge) {
		if (kind == "FunctionExpression" || kind == "WindowExpression") {
			auto name = Lower(Field(value, "function_name"));
			functions[name]++;
			auto catalog = Field(value, "catalog");
			if (policy.catalogs && !catalog.empty() && !policy.allowed_catalogs.count(catalog))
				Reject("catalog is not allowed: " + catalog);
			if (!policy.dynamic_sql && ((edge == "function" && (name == "query" || name == "query_table" ||
			                                                    name == "json_execute_serialized_sql")) ||
			                            name == "json_serialize_plan"))
				Reject("dynamic SQL is disabled: " + name);
		}
		if (kind == "RecursiveCTENode" && !policy.recursive)
			Reject("recursive CTEs are disabled");
		if (kind == "TableFunctionRef") {
			if (!policy.table_functions)
				Reject("table functions are disabled");
		}
		if (kind != "BaseTableRef" && kind != "ShowRef")
			return;
		auto catalog = Field(value, "catalog_name"), schema = Field(value, "schema_name"),
		     table = Field(value, "table_name");
		if (policy.catalogs && !catalog.empty() && !policy.allowed_catalogs.count(catalog))
			Reject("catalog is not allowed: " + catalog);
		if (kind == "ShowRef") {
			if (yyjson_obj_get(value, "query"))
				return;
			if (policy.tables)
				Reject("schema-wide SHOW is disabled by table policy");
			if (policy.schemas && (schema.empty() || !policy.allowed_schemas.count(schema)))
				Reject("SHOW requires an allowed schema");
			return;
		}
		if (catalog.empty() && schema.empty() && scope.count(Lower(table)))
			return;
		if (!policy.file_tables && FileName(table))
			Reject("file table reference is disabled: " + table);
		if (!policy.defer_table_checks && policy.schemas && (schema.empty() || !policy.allowed_schemas.count(schema)))
			Reject("schema is not allowed: " + schema);
		if (!policy.defer_table_checks && policy.tables && !policy.allowed_tables.count({catalog, schema, table}))
			Reject("table is not allowed: " + schema + "." + table);
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
			throw Stop{"AST size or depth limit exceeded"};
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
		return {false, "unsupported", "", "", {error.message}};
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
			walker.Reject(message);
		}
	}
	return {walker.violations.empty(), walker.violations.empty() ? "ok" : "forbidden", "", "", walker.violations};
}
} // namespace gatekeeper
