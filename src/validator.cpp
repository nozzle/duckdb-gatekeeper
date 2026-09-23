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
// The node's offset in the caller's text, or -1 when the serializer recorded none.
static int64_t Position(Json *node) {
	auto location = yyjson_obj_get(node, "query_location");
	return yyjson_is_uint(location) ? int64_t(yyjson_get_uint(location)) : -1;
}
std::string Lower(std::string value) {
	for (auto &c : value)
		if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';
	return value;
}
std::string TableRefPath(const std::string &catalog, const std::string &schema, const std::string &table) {
	std::string path = catalog;
	if (!schema.empty())
		path += (path.empty() ? "" : ".") + schema;
	path += (path.empty() ? "" : ".") + table;
	return Lower(path);
}
static void Invalid(const std::string &message) { throw std::invalid_argument(message); }
static bool TableMatches(const std::set<Table> &rules, const std::string &catalog, const std::string &schema,
                         const std::string &table, bool internal = false) {
	auto folded_catalog = Lower(catalog), folded_schema = Lower(schema), folded_table = Lower(table);
	// Exact schema/table names are required for internal objects, even when the resolved name is '*'.
	if (internal && (folded_schema == "*" || folded_table == "*"))
		return false;
	for (const auto &c : {folded_catalog, std::string("*"), std::string()}) {
		if (rules.count({c, folded_schema, folded_table}))
			return true;
		if (!internal &&
		    (rules.count({c, "*", folded_table}) || rules.count({c, folded_schema, "*"}) || rules.count({c, "*", "*"})))
			return true;
	}
	return false;
}

bool TableBlocked(const Policy &policy, const std::string &catalog, const std::string &schema,
                  const std::string &table) {
	return TableMatches(policy.blocked_tables, catalog, schema, table);
}

bool TableAllowed(const Policy &policy, const std::string &catalog, const std::string &schema, const std::string &table,
                  bool internal) {
	return !TableBlocked(policy, catalog, schema, table) &&
	       ((!policy.tables && !internal) || TableMatches(policy.allowed_tables, catalog, schema, table, internal));
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
	auto canonical = CanonicalFunction(name);
	// Parquet aliases share a permission; JSON aliases accept the canonical extraction name.
	return !FunctionDenied(policy, name) &&
	       (policy.allowed_functions.count(Lower(name)) || policy.allowed_functions.count(canonical) ||
	        (canonical == "read_parquet" && policy.allowed_functions.count("parquet_scan")) ||
	        (policy.defaults && inventory.defaults.count(Lower(name))));
}

bool Provenance::CallerCanName(const BindingPolicy &binding, const std::string &name) const {
	auto canonical = CanonicalFunction(name);
	return binding.caller_functions.count(canonical) || binding.synthesized_functions.count(canonical) ||
	       binding.literal_constructors.count(canonical) || caller_expansions.count(canonical) ||
	       (binding.caller_collates && CollationFunction(canonical));
}

bool Provenance::Attributable(const BindingPolicy &binding, const std::string &name) const {
	if (unattributed)
		return false;
	// A name the caller can produce, or that the caller's own binders retrieved, is the caller's. A name only a
	// trusted body introduced is not; when both did, the caller's rules apply query-wide.
	return CallerCanName(binding, name) || caller_lookups.count(CanonicalFunction(name));
}
Table ObjectKey(const std::string &catalog, const std::string &schema, const std::string &table) {
	return {Lower(catalog), Lower(schema), Lower(table)};
}
bool NamesObject(const std::set<Table> &written, const std::string &catalog, const std::string &schema,
                 const std::string &table) {
	auto key = ObjectKey(catalog, schema, table);
	for (const auto &ref : written) {
		if (ref.table != key.table)
			continue;
		if (!ref.catalog.empty()) {
			if (ref.catalog == key.catalog && (ref.schema.empty() || ref.schema == key.schema))
				return true;
			continue;
		}
		// Two parts: schema.table, or catalog.table with the catalog's default schema.
		if (ref.schema.empty() || ref.schema == key.schema || ref.schema == key.catalog)
			return true;
	}
	return false;
}
bool Provenance::CallerNamesObject(const BindingPolicy &binding, const std::string &catalog, const std::string &schema,
                                   const std::string &table) const {
	return NamesObject(binding.caller_table_names, catalog, schema, table);
}
bool Provenance::ObjectAttributable(const BindingPolicy &binding, const std::string &catalog, const std::string &schema,
                                    const std::string &table) const {
	if (unattributed)
		return false;
	auto key = ObjectKey(catalog, schema, table);
	if (caller_objects.count(key) || CallerNamesObject(binding, catalog, schema, table))
		return true;
	return !trusted_objects.count(key);
}
struct Stop {
	std::string message;
	std::string rule = rules::UNSUPPORTED_STRUCTURE;
};
struct Walker {
	const Inventory &inventory;
	Layers layers;
	BindingPolicy *binding;
	const Limits &limits;
	std::set<Violation> violations;
	std::map<std::string, size_t> functions;
	std::map<std::string, int64_t> function_positions;
	uint64_t nodes = 0;
	struct Work {
		Json *value;
		std::string expected;
		size_t depth;
		std::string edge;
	};
	std::vector<Work> pending;
	// The arguments of a call as the serializer lists them, in call order: DuckDB 1.5 writes the child
	// expressions, 2.0 writes {name, expression} pairs (FunctionArgument) with the expression as the value.
	static std::vector<Json *> Arguments(Json *call) {
		std::vector<Json *> arguments;
		size_t i, n;
		Json *item;
		yyjson_arr_foreach(yyjson_obj_get(call, "children"), i, n, item) arguments.push_back(item);
		yyjson_arr_foreach(yyjson_obj_get(call, "arguments"), i, n, item)
		    arguments.push_back(yyjson_obj_get(item, "expression"));
		return arguments;
	}
	// The value of a table-function argument. `name = value` reaches the binder as a comparison on a single-part
	// column reference, which it unwraps as a named parameter on both engines (bind_table_function.cpp); the
	// name is not an argument. A 2.0 `name := value` argument already carries its value as the expression.
	static Json *ArgumentValue(Json *argument) {
		if (Field(argument, "type") == "COMPARE_EQUAL" &&
		    Field(yyjson_obj_get(argument, "left"), "class") == "COLUMN_REF" &&
		    yyjson_arr_size(yyjson_obj_get(yyjson_obj_get(argument, "left"), "column_names")) == 1)
			return yyjson_obj_get(argument, "right");
		return argument;
	}
	// Recognize syntax, never evaluate it. Literal containers are permitted only in
	// contexts that require them; casts must have literal-form children.
	bool BindLiteral(Json *value, bool containers = false, bool pivot_names = false) {
		std::vector<Json *> work{value};
		uint64_t visited = 0;
		while (!work.empty()) {
			auto expr = work.back();
			work.pop_back();
			++visited;
			if (visited > limits.nodes)
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
			if (!yyjson_is_arr(yyjson_obj_get(expr, "children")) && !yyjson_is_arr(yyjson_obj_get(expr, "arguments")))
				return false;
			for (auto argument : Arguments(expr))
				work.push_back(argument);
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
			if (visited > limits.nodes)
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
			for (auto key : {"children", "arguments", "expression", "child", "left", "right", "input", "lower", "upper",
			                 "else_expr", "case_checks", "when_expr", "then_expr"}) {
				auto child = yyjson_obj_get(expr, key);
				if (child)
					work.push_back(child);
			}
		}
		return false;
	}
	void BindTime(Json *expr, const std::string &context, bool containers = false, bool pivot_names = false) {
		if (expr && !BindLiteral(expr, containers, pivot_names))
			Reject(rules::BIND_TIME_EXPRESSION, context + " requires a literal or bindable parameter", expr);
	}
	void Implied(const Names &names) {
		if (binding)
			binding->synthesized_functions.insert(names.begin(), names.end());
	}
	// One occurrence of a function name, written or implied by syntax. The position reported for a denied name
	// is the earliest query_location among all of its occurrences; nodes without one contribute nothing.
	void Function(const std::string &written, Json *value) {
		auto name = Lower(written);
		functions[name]++;
		auto position = Position(value);
		auto found = function_positions.find(name);
		if (position >= 0 && (found == function_positions.end() || position < found->second))
			function_positions[name] = position;
	}
	void Type(Json *value, size_t depth) {
		auto id = Field(value, "id");
		auto info = yyjson_obj_get(value, "type_info");
		if (id == "UNBOUND" || id == "USER") {
			auto expr = yyjson_obj_get(info, "expr");
			if (expr) {
				if (Field(expr, "class") != "TYPE")
					throw Stop{"computed type expressions are unsupported"};
				pending.push_back({expr, "ParsedExpression", depth + 1, "type"});
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
			pending.push_back({child, "logical_type", depth + 1, "type"});
		auto children = yyjson_obj_get(info, "child_types");
		if (children) {
			if (!yyjson_is_arr(children))
				throw Stop{"invalid nested type list"};
			size_t i, n;
			Json *entry;
			yyjson_arr_foreach(children, i, n, entry)
			    pending.push_back({yyjson_obj_get(entry, "second"), "logical_type", depth + 1, "type"});
		}
	}
	void Reject(const std::string &rule, const std::string &message, Json *node = nullptr,
	            const std::string &function = {}) {
		violations.emplace(rule, message, Field(node, "catalog_name"), Field(node, "schema_name"),
		                   Field(node, "table_name"), function, Position(node));
	}
	void References(Json *value, const std::string &kind, const std::string &edge) {
		// Every table name the caller wrote, whatever it turns out to be: a CTE, a catalog object, or a path a
		// replacement scan turns into a reader. Only the last matters to the replacement callback, which learns
		// which names are which and treats the rest as trusted. The same names, as written components, are what
		// the catalog callback and the plan walk attribute to the caller wherever they resolve.
		if (kind == "BaseTableRef" && binding) {
			auto catalog = Field(value, "catalog_name"), schema = Field(value, "schema_name"),
			     table = Field(value, "table_name");
			binding->caller_table_refs.insert(TableRefPath(catalog, schema, table));
			binding->caller_table_names.insert({Lower(catalog), Lower(schema), Lower(table)});
		}
		// COLLATE binds the collation's function without naming it; the choice is still the caller's.
		if (kind == "CollateExpression" && binding)
			binding->caller_collates = true;
		if (kind == "LimitModifier" || kind == "LimitPercentModifier" || kind == "LegacyLimitPercentModifier") {
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
				Reject(rules::BIND_TIME_EXPRESSION, "sample size requires a literal", value);
		}
		if (kind == "CastExpression") {
			// DuckDB 2.0 writes the target as a type expression (1.5 wrote a bound LogicalType, checked by Type()).
			// Only a named type is a cast target; a computed one is not a type the grammar can read.
			auto target = yyjson_obj_get(value, "type_expr");
			if (target && Field(target, "class") != "TYPE")
				throw Stop{"computed type expressions are unsupported"};
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
			auto arguments = Arguments(value);
			if (edge == "function") {
				static const Names runtime_capable = {"unnest", "range", "generate_series"};
				bool runtime = false;
				if (runtime_capable.count(name)) {
					for (auto argument : arguments)
						runtime = runtime || HasRuntimeReference(ArgumentValue(argument));
				}
				if (runtime && binding)
					binding->runtime_table_functions.insert(name);
				if (!runtime) {
					for (auto argument : arguments)
						BindTime(ArgumentValue(argument), "table-function argument", true);
				}
			}
			if (name == "unnest") {
				for (size_t i = 1; i < arguments.size(); i++)
					BindTime(arguments[i], "UNNEST option");
			}
			static const Names quantiles = {"quantile", "quantile_cont", "quantile_disc", "approx_quantile",
			                                "reservoir_quantile"};
			if (quantiles.count(name)) {
				auto orders = yyjson_obj_get(yyjson_obj_get(value, "order_bys"), "orders");
				size_t fraction = arguments.size() == 1 && yyjson_arr_size(orders) ? 0 : 1;
				for (size_t i = fraction; i < arguments.size(); i++)
					BindTime(arguments[i], "quantile fraction/options", true);
			}
			Function(name, value);
			// The aggregate these dispatch to is selected by a caller-supplied (foldable) expression that only
			// binding resolves; remember that the caller wrote the dispatcher so the bound target is allowlisted.
			if (binding && DispatchingAggregators().count(name))
				binding->caller_dispatchers.insert(name);
			// Dynamic SQL and plan inspection bind caller-supplied SQL at execution time, outside this
			// validation. They are on the never-bind list; this is the earlier, more specific diagnostic.
			if ((edge == "function" &&
			     (name == "query" || name == "query_table" || name == "json_execute_serialized_sql")) ||
			    name == "json_serialize_plan")
				violations.emplace(rules::DYNAMIC_SQL, "dynamic SQL is never allowed: " + name, Field(value, "catalog"),
				                   Field(value, "schema"), "", name, Position(value));
		}
		if (kind != "ShowRef")
			return;
		if (yyjson_obj_get(value, "query"))
			return;
		if (!layers.All([](const Policy &p) { return !p.tables && p.blocked_tables.empty(); }))
			Reject(rules::TABLE, "schema-wide SHOW is disabled by table policy", value);
	}
	void Check(Json *value, std::string expected, size_t depth = 0, std::string edge = {}) {
		pending.push_back({value, std::move(expected), depth, std::move(edge)});
		while (!pending.empty()) {
			auto work = std::move(pending.back());
			pending.pop_back();
			CheckNode(work.value, std::move(work.expected), work.depth, std::move(work.edge));
		}
	}
	void CheckNode(Json *value, std::string expected, size_t depth, std::string edge) {
		++nodes;
		if (nodes > limits.nodes || depth > limits.depth)
			throw Stop{"AST size or depth limit exceeded", rules::LIMIT};
		if (expected == "logical_type") {
			Type(value, depth);
			return;
		}
		// TYPE constants carry nested type expressions too; literal payloads otherwise remain opaque.
		if (expected == "opaque" && Field(yyjson_obj_get(value, "type"), "id") == "TYPE") {
			pending.push_back({yyjson_obj_get(value, "value"), "logical_type", depth + 1, "type"});
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
			    pending.push_back({child, expected.substr(0, expected.size() - 2), depth + 1, {}});
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
		// DuckDB 1.5: SHOW_UNQUALIFIED is `SHOW name` and the catalog-wide forms alike, all bound as DESCRIBE or
		// as SQL over the duckdb_* readers, which the never-bind list then refuses. DuckDB 2.0 splits it:
		// SHOW_SPECIAL keeps the catalog-wide forms on that path; SHOW (`SHOW name`) may instead read a setting's
		// value at bind time into the plan, autoloading extensions on the way, with no function for the
		// never-bind list to see (Binder::TryBindShowSetting). That kind is refused; DESCRIBE name remains.
		static const Names show_kinds = {"SHOW_FROM", "SHOW_UNQUALIFIED", "SHOW_SPECIAL", "DESCRIBE", "SUMMARY"};
		static const Names set_operations = {"UNION", "EXCEPT", "INTERSECT", "UNION_BY_NAME"};
		if (expected == "ShowRef" && !show_kinds.count(Field(value, "show_type")))
			throw Stop{"unsupported SHOW kind"};
		if (expected == "SetOperationNode" && !set_operations.count(Field(value, "setop_type")))
			throw Stop{"unsupported set operation"};
		if (expected == "SetOperationNode") {
			auto children = yyjson_obj_get(value, "children");
			auto left = yyjson_obj_get(value, "left"), right = yyjson_obj_get(value, "right");
			// DuckDB's default serializer emits a pair; Latest() emits a list. Validate both shapes
			// so native AST tests can use json_serialize_sql while production uses Latest().
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
				pending.push_back({child, "cte_entry", depth + 1, {}});
				auto name = Lower(Field(child, "key"));
				if (!declared.insert(name).second)
					throw Stop{"duplicate CTE"};
			}
		}
		yyjson_obj_foreach(value, i, n, key, child) {
			auto name = Text(key);
			if (name == "cte_map")
				continue;
			pending.push_back({child, rule.fields.at(name), depth + 1, name});
		}
		References(value, expected, edge);
	}
};

Result Validate(Json *root, const Policy &policy, BindingPolicy *binding, const Policy *ceiling, const Limits &limits) {
	auto &inventory = GetInventory();
	// Without a ceiling the one policy stands in both positions, as on an enforced connection.
	Walker walker{inventory, Layers{ceiling ? *ceiling : policy, policy}, binding, limits};
	try {
		walker.Check(root, "root");
	} catch (const Stop &error) {
		return {false,
		        error.rule == rules::LIMIT ? codes::FORBIDDEN : codes::UNSUPPORTED,
		        "",
		        "",
		        {{error.rule, error.message}}};
	}
	for (auto &entry : walker.functions) {
		auto &name = entry.first;
		if (binding)
			binding->caller_functions.insert(CanonicalFunction(name));
		if (!walker.layers.All([&](const Policy &p) { return FunctionAllowed(p, name); })) {
			auto canonical = CanonicalFunction(name);
			auto message = "function is not allowed: " + canonical;
			if (entry.second > 1)
				message += " (" + std::to_string(entry.second) + " occurrences)";
			auto found = walker.function_positions.find(name);
			walker.violations.emplace(rules::FUNCTION, message, "", "", "", canonical,
			                          found == walker.function_positions.end() ? -1 : found->second);
		}
	}
	return {walker.violations.empty(), walker.violations.empty() ? codes::OK : codes::FORBIDDEN, "", "",
	        walker.violations};
}
} // namespace gatekeeper
