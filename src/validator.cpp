#include "validator.hpp"
#include "function_policy.hpp"
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
bool TableAllowed(const Policy &policy, const std::string &catalog, const std::string &schema, const std::string &table,
                  bool internal) {
	if (!policy.tables && !internal)
		return true;
	auto folded_catalog = Lower(catalog), folded_schema = Lower(schema), folded_table = Lower(table);
	// Exact schema/table names are required for internal objects, even when the resolved name is '*'.
	if (internal && (folded_schema == "*" || folded_table == "*"))
		return false;
	for (const auto &c : {folded_catalog, std::string("*"), std::string()}) {
		if (policy.allowed_tables.count({c, folded_schema, folded_table}))
			return true;
		if (!internal &&
		    (policy.allowed_tables.count({c, "*", folded_table}) ||
		     policy.allowed_tables.count({c, folded_schema, "*"}) || policy.allowed_tables.count({c, "*", "*"})))
			return true;
	}
	return false;
}

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
	    {"TYPE", {"TYPE"}},
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

static const Inventory &GetInventory() {
	static const Inventory inventory;
	return inventory;
}

bool FunctionAllowed(const Policy &policy, const std::string &name) {
	auto &inventory = GetInventory();
	return !FunctionDenied(policy, name) && (!policy.functions || policy.allowed_functions.count(Lower(name)) ||
	                                         policy.allowed_functions.count(CanonicalFunction(name)) ||
	                                         (policy.defaults && inventory.defaults.count(Lower(name))));
}

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
	BindingPolicy *binding;
	const Policy *ceiling;
	template <class Predicate> bool Both(Predicate predicate) const {
		return predicate(policy) && (!ceiling || predicate(*ceiling));
	}
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
	// Recognize syntax, never evaluate it. Literal containers are permitted only in
	// contexts that require them; casts must have literal-form children.
	bool BindLiteral(Json *value, bool containers = false, bool pivot_names = false) {
		std::vector<Json *> work{value};
		uint64_t visited = 0;
		while (!work.empty()) {
			auto expr = work.back();
			work.pop_back();
			++visited;
			if (!Both([&](const Policy &p) { return visited <= p.nodes; }))
				return false;
			auto kind = Field(expr, "class");
			if (kind == "CONSTANT" || kind == "PARAMETER")
				continue;
			if (pivot_names && kind == "COLUMN_REF" && yyjson_arr_size(yyjson_obj_get(expr, "column_names")) == 1)
				continue;
			if (kind == "CAST") {
				work.push_back(yyjson_obj_get(expr, "child"));
				continue; // The normal type walk checks target types and parameters.
			}
			auto name = Lower(Field(expr, "function_name"));
			bool container = containers && ((kind == "OPERATOR" && Field(expr, "type") == "ARRAY_CONSTRUCTOR") ||
			                                (kind == "FUNCTION" && (name == "list_value" || name == "struct_pack" ||
			                                                        (pivot_names && name == "row"))));
			if (!container)
				return false;
			if (binding && kind == "OPERATOR")
				binding->literal_constructors.insert("list_value");
			if (yyjson_obj_get(expr, "filter") ||
			    yyjson_arr_size(yyjson_obj_get(yyjson_obj_get(expr, "order_bys"), "orders")))
				return false;
			if (binding && kind == "FUNCTION")
				binding->literal_constructors.insert(name);
			if ((!Field(expr, "catalog").empty() && Lower(Field(expr, "catalog")) != "system") ||
			    (!Field(expr, "schema").empty() && Lower(Field(expr, "schema")) != "main"))
				return false;
			auto children = yyjson_obj_get(expr, "children");
			if (!yyjson_is_arr(children))
				return false;
			size_t i, n;
			Json *child;
			yyjson_arr_foreach(children, i, n, child) work.push_back(child);
		}
		return true;
	}
	bool HasRuntimeReference(Json *value) {
		std::vector<Json *> work{value};
		uint64_t visited = 0;
		while (!work.empty()) {
			auto expr = work.back();
			work.pop_back();
			++visited;
			if (!Both([&](const Policy &p) { return visited <= p.nodes; }))
				return false;
			if (yyjson_is_arr(expr)) {
				size_t i, n;
				Json *child;
				yyjson_arr_foreach(expr, i, n, child) work.push_back(child);
				continue;
			}
			auto kind = Field(expr, "class");
			if (kind == "COLUMN_REF" || kind == "SUBQUERY")
				return true;
			// Never mistake literal payloads, type metadata or lambda variables for row references.
			if (kind == "CONSTANT" || kind == "TYPE" || kind == "LAMBDA")
				continue;
			for (auto key : {"children", "child", "left", "right", "input", "lower", "upper", "else_expr",
			                 "case_checks", "when_expr", "then_expr"}) {
				auto child = yyjson_obj_get(expr, key);
				if (child)
					work.push_back(child);
			}
		}
		return false;
	}
	void BindTime(Json *expr, const std::string &context, bool containers = false, bool pivot_names = false) {
		if (expr && !BindLiteral(expr, containers, pivot_names))
			Reject("bind_time_expression", context + " requires a literal or bindable parameter", expr);
	}
	void Implied(const Names &names) {
		if (binding)
			binding->synthesized_functions.insert(names.begin(), names.end());
	}
	void Function(const std::string &name, Json *value) {
		functions[Lower(name)]++;
		auto location = yyjson_obj_get(value, "query_location");
		if (yyjson_is_uint(location))
			function_positions.emplace(Lower(name), int64_t(yyjson_get_uint(location)));
	}
	void Type(Json *value, size_t depth) {
		auto id = Field(value, "id");
		auto info = yyjson_obj_get(value, "type_info");
		if (id == "UNBOUND" || id == "USER") {
			auto expr = yyjson_obj_get(info, "expr");
			if (expr) {
				if (Field(expr, "class") != "TYPE")
					throw Stop{"computed type expressions are unsupported"};
				pending.push_back({expr, "ParsedExpression", {}, depth + 1, "type"});
			} else {
				if (Field(info, "name").empty())
					throw Stop{"missing type name"};
			}
			return;
		}
		if (id.empty())
			throw Stop{"missing logical type id"};
		if (!info)
			return;
		auto child = yyjson_obj_get(info, "child_type");
		if (child)
			pending.push_back({child, "logical_type", {}, depth + 1, "type"});
		auto children = yyjson_obj_get(info, "child_types");
		if (children) {
			if (!yyjson_is_arr(children))
				throw Stop{"invalid nested type list"};
			size_t i, n;
			Json *entry;
			yyjson_arr_foreach(children, i, n, entry)
			    pending.push_back({yyjson_obj_get(entry, "second"), "logical_type", {}, depth + 1, "type"});
		}
	}
	void Reject(const std::string &rule, const std::string &message, Json *node = nullptr,
	            const std::string &function = {}) {
		auto location = yyjson_obj_get(node, "query_location");
		violations.emplace(rule, message, Field(node, "catalog_name"), Field(node, "schema_name"),
		                   Field(node, "table_name"), function,
		                   yyjson_is_uint(location) ? int64_t(yyjson_get_uint(location)) : -1);
	}
	void References(Json *value, const std::string &kind, const Names &scope, const std::string &edge) {
		if (kind == "LimitModifier" || kind == "LimitPercentModifier") {
			BindTime(yyjson_obj_get(value, "limit"), "LIMIT");
			BindTime(yyjson_obj_get(value, "offset"), "OFFSET");
		}
		if (kind == "AtClause")
			BindTime(yyjson_obj_get(value, "expr"), "AT clause");
		if (kind == "StarExpression")
			BindTime(yyjson_obj_get(value, "expr"), "COLUMNS", true);
		if (kind == "PivotColumnEntry")
			BindTime(yyjson_obj_get(value, "star_expr"), "PIVOT IN", true, true);
		if (kind == "SampleOptions") {
			// sample_size is already a serialized Value in the pinned grammar.
			auto sample = yyjson_obj_get(value, "sample_size");
			if (sample &&
			    (!yyjson_is_obj(sample) || !yyjson_obj_get(sample, "type") || yyjson_obj_get(sample, "class")))
				Reject("bind_time_expression", "sample size requires a literal", value);
		}
		if (kind == "TypeExpression") {
			auto children = yyjson_obj_get(value, "children");
			size_t i, n;
			Json *child;
			yyjson_arr_foreach(children, i, n, child) {
				if (Field(child, "class") != "TYPE")
					BindTime(child, "type parameter");
			}
		}
		if (kind == "OperatorExpression") {
			auto type = Field(value, "type");
			if (type == "ARRAY_CONSTRUCTOR")
				Function("list_value", value);
			if (type == "ARRAY_SLICE")
				Function("array_slice", value);
			if (type == "ARROW")
				Function("json_extract", value);
			if (type == "ARRAY_EXTRACT")
				Implied({"array_extract", "map_extract_value", "json_extract", "variant_extract"});
			if (type == "STRUCT_EXTRACT")
				Implied({"struct_extract", "union_extract", "map_extract_value", "json_extract", "variant_extract"});
		}
		if (kind == "LambdaExpression" && Field(value, "syntax_type") != "LAMBDA_KEYWORD")
			Implied({"json_extract"});
		if (kind == "ColumnRefExpression") {
			auto columns = yyjson_obj_get(value, "column_names");
			if (yyjson_arr_size(columns) > 1)
				Implied({"struct_extract", "struct_pack", "union_extract", "map_extract_value", "json_extract",
				         "variant_extract"});
			else {
				// An unresolved single-part table alias can become a whole-row struct.
				Implied({"struct_pack"});
				auto name = Lower(Text(yyjson_arr_get(columns, 0)));
				static const std::map<std::string, std::string> sql_values = {
				    {"current_catalog", "current_catalog"},
				    {"current_schema", "current_schema"},
				    {"current_date", "current_date"},
				    {"current_time", "get_current_time"},
				    {"current_timestamp", "get_current_timestamp"},
				    {"current_user", "current_user"},
				    {"current_role", "current_role"},
				    {"session_user", "session_user"},
				    {"user", "user"},
				    {"localtime", "current_localtime"},
				    {"localtimestamp", "current_localtimestamp"}};
				auto found = sql_values.find(name);
				if (found != sql_values.end())
					Implied({found->second});
			}
		}
		if (kind == "FunctionExpression" || kind == "WindowExpression") {
			auto name = Lower(Field(value, "function_name"));
			auto children = yyjson_obj_get(value, "children");
			size_t i, n;
			Json *child;
			if (edge == "function") {
				bool runtime = false;
				if (Names{"unnest", "range", "generate_series"}.count(name)) {
					yyjson_arr_foreach(children, i, n, child) {
						auto argument = child;
						if (Field(child, "type") == "COMPARE_EQUAL" &&
						    Field(yyjson_obj_get(child, "left"), "class") == "COLUMN_REF" &&
						    yyjson_arr_size(yyjson_obj_get(yyjson_obj_get(child, "left"), "column_names")) == 1)
							argument = yyjson_obj_get(child, "right");
						runtime = runtime || HasRuntimeReference(argument);
					}
				}
				if (runtime && binding)
					binding->runtime_table_functions.insert(name);
				yyjson_arr_foreach(children, i, n, child) {
					auto argument = child;
					if (Field(child, "type") == "COMPARE_EQUAL" &&
					    Field(yyjson_obj_get(child, "left"), "class") == "COLUMN_REF" &&
					    yyjson_arr_size(yyjson_obj_get(yyjson_obj_get(child, "left"), "column_names")) == 1)
						argument = yyjson_obj_get(child, "right");
					if (!runtime)
						BindTime(argument, "table-function argument", true);
				}
			}
			if (name == "unnest") {
				yyjson_arr_foreach(children, i, n, child) if (i > 0) BindTime(child, "UNNEST option");
			}
			if (Names{"quantile", "quantile_cont", "quantile_disc", "approx_quantile", "reservoir_quantile"}.count(
			        name)) {
				auto orders = yyjson_obj_get(yyjson_obj_get(value, "order_bys"), "orders");
				size_t fraction = yyjson_arr_size(children) == 1 && yyjson_arr_size(orders) ? 0 : 1;
				yyjson_arr_foreach(children, i, n, child) if (i >= fraction)
				    BindTime(child, "quantile fraction/options", true);
			}
			functions[name]++;
			auto location = yyjson_obj_get(value, "query_location");
			if (yyjson_is_uint(location)) {
				auto position = int64_t(yyjson_get_uint(location));
				auto found = function_positions.find(name);
				if (position >= 0 && (found == function_positions.end() || position < found->second))
					function_positions[name] = position;
			}
			// Dynamic SQL and plan inspection bind caller-supplied SQL at execution time, outside this
			// validation. They are on the never-bind list; this is the earlier, more specific diagnostic.
			if ((edge == "function" &&
			     (name == "query" || name == "query_table" || name == "json_execute_serialized_sql")) ||
			    name == "json_serialize_plan")
				violations.emplace("dynamic_sql", "dynamic SQL is never allowed: " + name, Field(value, "catalog"),
				                   Field(value, "schema"), "", name,
				                   yyjson_is_uint(location) ? int64_t(yyjson_get_uint(location)) : -1);
		}
		if (kind == "RecursiveCTENode" && !Both([](const Policy &p) { return p.recursive; }))
			Reject("recursive_cte", "recursive CTEs are disabled", value);
		if (kind != "BaseTableRef" && kind != "ShowRef")
			return;
		auto catalog = Field(value, "catalog_name"), schema = Field(value, "schema_name"),
		     table = Field(value, "table_name");
		if (kind == "ShowRef") {
			if (yyjson_obj_get(value, "query"))
				return;
			if (!Both([](const Policy &p) { return !p.tables; }))
				Reject("table", "schema-wide SHOW is disabled by table policy", value);
			return;
		}
		if (catalog.empty() && schema.empty() && scope.count(Lower(table)))
			return;
		// Match ReplacementScanInput::GetFullPath, including unquoted dotted names.
		std::string path;
		for (const auto &part : {catalog, schema, table}) {
			if (part.empty())
				continue;
			if (!path.empty())
				path += ".";
			path += part;
		}
		// Preflight: file-shaped names cannot be catalog objects unless replacement scans are enabled.
		// The authoritative check is the Gatekeeper replacement scan installed at LOAD.
		if (!Both([](const Policy &p) { return p.replacement_scans; }) && (FileName(table) || FileName(path)))
			Reject("replacement_scan", "replacement scans are disabled: " + path, value);
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
		++nodes;
		if (!Both([&](const Policy &p) { return nodes <= p.nodes && depth <= p.depth; }))
			throw Stop{"AST size or depth limit exceeded", "limit"};
		if (expected == "logical_type") {
			Type(value, depth);
			return;
		}
		// TYPE constants carry nested type expressions too; literal payloads otherwise remain opaque.
		if (expected == "opaque" && Field(yyjson_obj_get(value, "type"), "id") == "TYPE") {
			pending.push_back({yyjson_obj_get(value, "value"), "logical_type", {}, depth + 1, "type"});
			return;
		}
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
		if (expected == "SetOperationNode") {
			auto children = yyjson_obj_get(value, "children");
			auto left = yyjson_obj_get(value, "left"), right = yyjson_obj_get(value, "right");
			// SetOperationNode::SerializeChildNode emits either the legacy pair or the latest list.
			if (children) {
				if (left || right || !yyjson_is_arr(children) || yyjson_arr_size(children) < 2)
					throw Stop{"set operation requires either left/right or at least two children"};
			} else if (!yyjson_is_obj(left) || !yyjson_is_obj(right)) {
				throw Stop{"set operation requires either left/right or at least two children"};
			}
		}
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

Result Validate(Json *root, const Policy &policy, BindingPolicy *binding, const Policy *ceiling) {
	auto &inventory = GetInventory();
	Walker walker{inventory, policy, binding, ceiling};
	try {
		walker.Check(root, "root");
	} catch (const Stop &error) {
		return {false, error.rule == "limit" ? "forbidden" : "unsupported", "", "", {{error.rule, error.message}}};
	}
	for (auto &entry : walker.functions) {
		auto &name = entry.first;
		if (!walker.Both([&](const Policy &p) { return FunctionAllowed(p, name); })) {
			auto canonical = CanonicalFunction(name);
			auto message = "function is not allowed: " + canonical;
			if (entry.second > 1)
				message += " (" + std::to_string(entry.second) + " occurrences)";
			auto found = walker.function_positions.find(name);
			walker.violations.emplace("function", message, "", "", "", canonical,
			                          found == walker.function_positions.end() ? -1 : found->second);
		}
	}
	return {walker.violations.empty(), walker.violations.empty() ? "ok" : "forbidden", "", "", walker.violations};
}
} // namespace gatekeeper
