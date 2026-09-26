#include "validator.hpp"
#include "function_policy.hpp"
#include "grammar.hpp"
#include "inventory.hpp"
#include <algorithm>
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
NamePath FoldPath(NamePath path) {
	for (auto &part : path)
		part = Lower(part);
	return path;
}
static void Invalid(const std::string &message) { throw std::invalid_argument(message); }
bool NamespaceMatches(const std::string &catalog, const NamePath &schema_path, const std::string &actual_catalog,
                      const NamePath &actual_schema_path, bool exact_schema) {
	if (actual_catalog.empty() || actual_schema_path.empty() || schema_path.size() != actual_schema_path.size())
		return false;
	if (!catalog.empty() && catalog != "*" && catalog != Lower(actual_catalog))
		return false;
	for (size_t i = 0; i < schema_path.size(); i++)
		if (actual_schema_path[i].empty() ||
		    (schema_path[i] != Lower(actual_schema_path[i]) && (exact_schema || schema_path[i] != "*")))
			return false;
	return true;
}
static bool TableMatches(const std::set<Table> &rules, const Table &key, bool internal = false) {
	// Exact schema/table names are required for internal objects, even when the resolved name is '*'.
	if (internal &&
	    (std::find(key.schema_path.begin(), key.schema_path.end(), "*") != key.schema_path.end() || key.table == "*"))
		return false;
	// Exact rules use the set index. Wildcard rules still require a linear scan; avoid enumerating
	// the exponentially many wildcard combinations of an arbitrarily deep schema path.
	if (rules.count(key))
		return true;
	for (const auto &rule : rules) {
		if (!NamespaceMatches(rule.catalog, rule.schema_path, key.catalog, key.schema_path, internal) ||
		    (rule.table != key.table && (internal || rule.table != "*")))
			continue;
		return true;
	}
	return false;
}

bool TableBlocked(const Policy &policy, const std::string &catalog, const NamePath &schema_path,
                  const std::string &table) {
	return TableMatches(policy.blocked_tables, ObjectKey(catalog, schema_path, table));
}

bool TableAllowed(const Policy &policy, const std::string &catalog, const NamePath &schema_path,
                  const std::string &table, bool internal) {
	auto key = ObjectKey(catalog, schema_path, table);
	return !TableMatches(policy.blocked_tables, key) &&
	       ((!policy.tables && !internal) || TableMatches(policy.allowed_tables, key, internal));
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
	std::set<FunctionGrant> defaults;
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
		auto entries = yyjson_obj_get(data, "defaults");
		if (!yyjson_is_arr(entries))
			throw std::runtime_error("invalid embedded default identities");
		yyjson_arr_foreach(entries, i, n, value) {
			FunctionGrant identity{Field(value, "catalog"), {}, Field(value, "name"), Field(value, "type")};
			auto path = yyjson_obj_get(value, "schema_path");
			if (!yyjson_is_arr(path))
				throw std::runtime_error("invalid embedded default schema_path");
			yyjson_arr_foreach(path, j, m, field) {
				auto part = Text(field);
				if (part.empty() || part == "*" || part != Lower(part) || part.find('\0') != std::string::npos)
					throw std::runtime_error("invalid embedded default schema component");
				identity.schema_path.push_back(part);
			}
			if (identity.catalog.empty() || identity.catalog == "*" || identity.schema_path.empty() ||
			    identity.name.empty() || !SupportedFunctionKind(identity.type) ||
			    identity.catalog != Lower(identity.catalog) || identity.name != Lower(identity.name) ||
			    identity.catalog.find('\0') != std::string::npos || identity.name.find('\0') != std::string::npos ||
			    !defaults.insert(identity).second)
				throw std::runtime_error("invalid embedded default identity");
		}
	}
};

static const Inventory &GetInventory() {
	static const Inventory inventory;
	return inventory;
}

bool SupportedFunctionKind(const std::string &kind) {
	static const Names kinds = {"scalar", "aggregate", "table", "macro", "table_macro", "window"};
	return kinds.count(kind);
}
bool SystemIdentity(const Identity &identity) {
	return !identity.name.empty() && Lower(identity.catalog) == "system" &&
	       FoldPath(identity.schema_path) == NamePath{"main"};
}
static bool GrantNameMatches(const FunctionGrant &rule, const std::string &name, bool aliases) {
	return rule.name == Lower(name) || (aliases && CanonicalFunction(rule.name) == CanonicalFunction(name));
}
static bool ReviewedAliases(const Identity &identity) {
	return SystemIdentity(identity) &&
	       ((identity.type == "table" && CanonicalFunction(identity.name) == "read_parquet") ||
	        (identity.type == "scalar" && (CanonicalFunction(identity.name) == "json_extract" ||
	                                       CanonicalFunction(identity.name) == "json_extract_string")));
}
static bool FunctionMatches(const FunctionGrant &rule, const Identity &identity) {
	return (rule.type.empty() || rule.type == identity.type) &&
	       GrantNameMatches(rule, identity.name, ReviewedAliases(identity)) &&
	       NamespaceMatches(rule.catalog, rule.schema_path, identity.catalog, identity.schema_path);
}
bool FunctionBlocked(const Policy &policy, const Identity &identity) {
	for (const auto &rule : policy.blocked_functions)
		if (FunctionMatches(rule, identity))
			return true;
	return false;
}

// Prove coverage of an eligible namespace pattern, not merely a matching leaf. A scoped block must
// wait for catalog resolution whenever another admitted identity could survive it. Enumerating kinds
// permits separate kind-specific blocks to cover an untyped grant without widening eligibility.
static bool BlockCovers(const FunctionGrant &block, const FunctionGrant &candidate) {
	if (!block.catalog.empty() && block.catalog != "*" && block.catalog != candidate.catalog)
		return false;
	if (block.schema_path.size() != candidate.schema_path.size())
		return false;
	for (size_t i = 0; i < block.schema_path.size(); i++)
		if (block.schema_path[i] != "*" && block.schema_path[i] != candidate.schema_path[i])
			return false;
	return (block.type.empty() || block.type == candidate.type) &&
	       GrantNameMatches(
	           block, candidate.name,
	           ReviewedAliases({candidate.catalog, candidate.schema_path, candidate.name, candidate.type}));
}
bool FunctionEligible(const Policy &policy, const std::string &name) {
	if (NeverBind(name))
		return false;
	auto survives = [&](const FunctionGrant &rule, bool defaults) {
		for (const auto &kind : {"scalar", "aggregate", "table", "macro", "table_macro", "window"}) {
			if (!rule.type.empty() && rule.type != kind)
				continue;
			FunctionGrant candidate{rule.catalog, rule.schema_path, Lower(name), kind};
			if (rule.name != candidate.name) {
				// Defaults are exact identities. Only explicit rules carry reviewed alias equivalence.
				if (defaults || !NamespaceMatches(rule.catalog, rule.schema_path, "system", {"main"}) ||
				    !ReviewedAliases({"system", {"main"}, name, kind}) ||
				    CanonicalFunction(rule.name) != CanonicalFunction(name))
					continue;
				candidate.catalog = "system";
				candidate.schema_path = {"main"};
			}
			bool covered = false;
			for (const auto &block : policy.blocked_functions)
				if (BlockCovers(block, candidate)) {
					covered = true;
					break;
				}
			if (!covered)
				return true;
		}
		return false;
	};
	if (policy.defaults)
		for (const auto &rule : GetInventory().defaults)
			if (survives(rule, true))
				return true;
	for (const auto &rule : policy.allowed_functions)
		if (survives(rule, false))
			return true;
	return false;
}
bool FunctionAllowed(const Policy &policy, const Identity &identity) {
	if (identity.name.empty() || identity.catalog.empty() || identity.schema_path.empty() ||
	    !SupportedFunctionKind(identity.type) || FunctionDenied(policy, identity))
		return false;
	for (const auto &part : identity.schema_path)
		if (part.empty())
			return false;
	if (policy.defaults && GetInventory().defaults.count({Lower(identity.catalog), FoldPath(identity.schema_path),
	                                                      Lower(identity.name), identity.type}))
		return true;
	for (const auto &rule : policy.allowed_functions)
		if (FunctionMatches(rule, identity))
			return true;
	return false;
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
Table ObjectKey(const std::string &catalog, const NamePath &schema_path, const std::string &table) {
	return {Lower(catalog), FoldPath(schema_path), Lower(table)};
}
bool NamesObject(const WrittenNames &written, const std::string &catalog, const NamePath &schema_path,
                 const std::string &table) {
	auto key = ObjectKey(catalog, schema_path, table);
	NamePath full{key.catalog};
	full.insert(full.end(), key.schema_path.begin(), key.schema_path.end());
	full.push_back(key.table);
	for (const auto &ref : written) {
		if (ref.empty() || ref.back() != key.table)
			continue;
		if (ref.size() <= full.size() && std::equal(ref.rbegin(), ref.rend(), full.rbegin()))
			return true;
		// catalog.table: the catalog's default schema is resolved by DuckDB.
		if (ref.size() == 2 && ref.front() == key.catalog)
			return true;
		// 1.5 can serialize catalog-only qualification with an empty schema placeholder.
		if (ref.size() == 3 && ref[0] == key.catalog && ref[1].empty())
			return true;
	}
	return false;
}
bool Provenance::CallerNamesObject(const BindingPolicy &binding, const std::string &catalog,
                                   const NamePath &schema_path, const std::string &table) const {
	return NamesObject(binding.caller_table_names, catalog, schema_path, table);
}
bool Provenance::ObjectAttributable(const BindingPolicy &binding, const std::string &catalog,
                                    const NamePath &schema_path, const std::string &table) const {
	if (unattributed)
		return false;
	auto key = ObjectKey(catalog, schema_path, table);
	if (caller_objects.count(key) || CallerNamesObject(binding, catalog, schema_path, table))
		return true;
	return !trusted_objects.count(key);
}
struct Stop {
	std::string message;
	std::string rule = rules::UNSUPPORTED_STRUCTURE;
};
// Preserve written components without guessing whether the first qualifier names a catalog.
static NamePath WrittenPath(Json *value, bool function = false) {
	NamePath path;
	if (auto qualified = yyjson_obj_get(value, "qualified_name")) {
		auto parts = yyjson_obj_get(qualified, "path");
		if (!yyjson_is_arr(parts))
			throw Stop{"invalid qualified name path"};
		size_t i, n;
		Json *part;
		yyjson_arr_foreach(parts, i, n, part) {
			if (!yyjson_is_str(part))
				throw Stop{"invalid qualified name component"};
			path.push_back(Text(part));
		}
		if (path.empty())
			throw Stop{"empty qualified name path"};
	} else {
		auto catalog = Field(value, function ? "catalog" : "catalog_name");
		auto schema = Field(value, function ? "schema" : "schema_name");
		if (!catalog.empty()) {
			path.push_back(catalog);
			path.push_back(schema);
		} else if (!schema.empty())
			path.push_back(schema);
		path.push_back(Field(value, function ? "function_name" : "table_name"));
	}
	return FoldPath(std::move(path));
}
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
			if (kind == "FUNCTION") {
				auto path = WrittenPath(expr, true);
				if (path != NamePath{name} && path != NamePath{"main", name} &&
				    path != NamePath{"system", "main", name} && path != NamePath{"system", "", name})
					return false;
			}
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
			for (const auto &name : names)
				binding->synthesized_functions.insert(CanonicalFunction(name));
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
		// Before binding a written qualifier is not a resolved catalog/schema identity.
		violations.emplace(rule, message, "", NamePath{}, Field(node, "table_name"), function, Position(node));
	}
	void References(Json *value, const std::string &kind, const std::string &edge) {
		if (kind == "ParameterExpression" && binding) {
			auto name = Lower(Field(value, "identifier"));
			auto position = Position(value);
			auto inserted = binding->caller_parameters.emplace(name, position);
			if (!inserted.second && position >= 0 && (inserted.first->second < 0 || position < inserted.first->second))
				inserted.first->second = position;
		}
		// Every table name the caller wrote, whatever it turns out to be: a CTE, a catalog object, or a path a
		// replacement scan turns into a reader. Only the last matters to the replacement callback, which learns
		// which names are which and treats the rest as trusted. The same names, as written components, are what
		// the catalog callback and the plan walk attribute to the caller wherever they resolve.
		if (kind == "BaseTableRef" && binding)
			binding->caller_table_names.insert(WrittenPath(value));
		// COLLATE binds the collation's function without naming it; the choice is still the caller's.
		if (kind == "CollateExpression" && binding) {
			binding->caller_collates = true;
			binding->caller_collation_names.insert(Lower(Field(value, "collation")));
		}
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
				Implied({"list_value"});
			if (type == "ARRAY_SLICE")
				Implied({"array_slice"});
			if (type == "ARROW")
				Implied({"json_extract"});
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
			if (yyjson_is_true(yyjson_obj_get(value, "is_operator")))
				Implied({name});
			// The parsed AST does not distinguish syntax-implied helpers from written calls, so both
			// receive the corresponding builtin syntax's system-origin requirement.
			if (name == "list_value" || name == "struct_pack" || name == "row" || name == "contains" ||
			    name == "regexp_full_match")
				Implied({name});
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
			// Only literal caller-selected aggregate names can be authorized before entering the dispatcher.
			if (binding && DispatchingAggregators().count(name)) {
				binding->caller_dispatchers.insert(name);
				// The engines resolve the argument as one leaf in system.main, never as SQL qualification.
				// Do not evaluate a foldable expression to discover what permission it needs.
				auto target = arguments.size() > 1 ? arguments[1] : nullptr;
				auto constant = yyjson_obj_get(target, "value");
				auto text = yyjson_obj_get(constant, "value");
				auto literal = yyjson_obj_get(target, "literal");
				if (Field(literal, "kind") == "STRING")
					text = yyjson_obj_get(literal, "text");
				// A dotted spelling may be rewritten to a method call with a prepended receiver. Our catalog
				// callback cannot identify that occurrence, so refuse it if it resolves to a system dispatcher.
				// Merely sharing a dispatcher leaf does not impose its argument contract on a host macro/UDF.
				if (WrittenPath(value, true).size() > 1 || Field(target, "class") != "CONSTANT" || !yyjson_is_str(text))
					binding->unsupported_dispatchers.insert(name);
				else {
					binding->dispatcher_targets.insert(Lower(Text(text)));
					binding->dispatcher_targets_by_name[name].insert(Lower(Text(text)));
				}
			}
			// Dynamic SQL and plan inspection bind caller-supplied SQL at execution time, outside this
			// validation. They are on the never-bind list; this is the earlier, more specific diagnostic.
			if ((edge == "function" &&
			     (name == "query" || name == "query_table" || name == "json_execute_serialized_sql")) ||
			    name == "json_serialize_plan")
				violations.emplace(rules::DYNAMIC_SQL, "dynamic SQL is never allowed: " + name, "", NamePath{}, "",
				                   name, Position(value));
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
		if (!walker.layers.All([&](const Policy &p) { return FunctionEligible(p, name); })) {
			auto canonical = CanonicalFunction(name);
			auto message = "function is not allowed: " + canonical;
			if (entry.second > 1)
				message += " (" + std::to_string(entry.second) + " occurrences)";
			auto found = walker.function_positions.find(name);
			walker.violations.emplace(rules::FUNCTION, message, "", NamePath{}, "", canonical,
			                          found == walker.function_positions.end() ? -1 : found->second);
		}
	}
	return {walker.violations.empty(), walker.violations.empty() ? codes::OK : codes::FORBIDDEN, "", "",
	        walker.violations};
}
} // namespace gatekeeper
