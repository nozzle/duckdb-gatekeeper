#pragma once
#include "yyjson.hpp"
#include <cstdint>
#include <map>
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
// The two layers every authorization consults: the global ceiling the host set, and the request layer, which is
// the ceiling with a gatekeeper_validate caller's options applied. An enforced connection has no request layer
// and puts its policy snapshot in both positions. Wherever both are checked, the ceiling is checked first; a
// statement both layers deny is described by the ceiling's rule.
struct Layers {
	const Policy &ceiling;
	const Policy &policy;
	template <class Fn> void Each(Fn &&fn) const {
		fn(ceiling);
		fn(policy);
	}
	template <class Predicate> bool All(Predicate &&predicate) const { return predicate(ceiling) && predicate(policy); }
};
// The codes a Result carries. ok, or the kind of refusal: forbidden and unsupported are decisions with violations,
// the other three describe an error in the caller's input or in the bind. Documented in docs/security.md and
// carried by every audit record.
namespace codes {
inline constexpr const char *OK = "ok";
inline constexpr const char *FORBIDDEN = "forbidden";
inline constexpr const char *UNSUPPORTED = "unsupported";
inline constexpr const char *INVALID_INPUT = "invalid_input";
inline constexpr const char *PARSER = "parser";
inline constexpr const char *BINDING = "binding";
} // namespace codes
// The rules a Violation names: which check refused. Unrelated to the identity type "table" and to the struct
// field "table", which are spelled out where they are used.
namespace rules {
inline constexpr const char *STATEMENT = "statement";
inline constexpr const char *LIMIT = "limit";
inline constexpr const char *FUNCTION = "function";
inline constexpr const char *TABLE = "table";
inline constexpr const char *INTERNAL_OBJECT = "internal_object";
inline constexpr const char *BIND_TIME_EXPRESSION = "bind_time_expression";
inline constexpr const char *DYNAMIC_SQL = "dynamic_sql";
inline constexpr const char *REPLACEMENT_SCAN = "replacement_scan";
inline constexpr const char *UNSUPPORTED_STRUCTURE = "unsupported_structure";
} // namespace rules
struct Violation {
	std::string rule, message, catalog, schema, table, function_name;
	int64_t position = -1;
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
// Results for the denials that more than one boundary reports, so every boundary spells each one the same way.
inline constexpr const char *UNSUPPORTED_STATEMENT = "only supported read statements are permitted";
// The private bind stopped short of a complete plan: a parameter without a value or a resolvable type. Thrown
// where the bind is checked, and the error_message of the gatekeeper_validate row when the engine reports it.
inline constexpr const char *PARAMETERS_REQUIRED =
    "Validation requires a complete bound plan; parameter values or types may be needed";
inline Result UnsupportedStatement() {
	return {false, codes::UNSUPPORTED, "", "", {{rules::STATEMENT, UNSUPPORTED_STATEMENT}}};
}
inline Result NotAdmitted() {
	return {false, codes::FORBIDDEN, "", "", {{rules::STATEMENT, "not admitted at the binding boundary"}}};
}
inline Result FixedLimitExceeded(std::string message) {
	return {false, codes::FORBIDDEN, "", "", {{rules::LIMIT, std::move(message)}}};
}
inline Result InvalidInput(std::string message) { return {false, codes::INVALID_INPUT, "", std::move(message)}; }
struct BindingPolicy {
	// Ambiguous caller syntax: enforce only the implementation actually looked up.
	Names synthesized_functions;
	Names literal_constructors;
	Names runtime_table_functions;
	// Caller-written list_aggregate/aggregate family calls: the aggregate they select by name is caller-chosen
	// text, so the bound implementation must pass the allowlists like any other caller-written function.
	Names caller_dispatchers;
	// Every function name the caller wrote, canonical: the names the text check decided, kept for the bind and
	// execution boundaries to tell the caller's functions from those a trusted definition introduces.
	Names caller_functions;
	// The caller wrote COLLATE: the collation's function (lower, strip_accents, ...) is the caller's choice,
	// though it never appears in the text.
	bool caller_collates = false;
	// Caller-written table references by qualified name (catalog.schema.table as written, case-folded). A
	// replacement scan for one of them substitutes a reader the caller chose, so that reader must pass the
	// allowlists like a caller-written table function. A replacement reached only through a trusted view or
	// macro body is that definition's own reader and is not subject to function policy, exactly like the
	// readers such bodies name explicitly. The replacement callback sees no origin, so a name both sides use
	// is checked as the caller's, query-wide, like other ambiguous caller syntax.
	Names caller_table_refs;
	// The same references as written components (catalog, schema, table; empty where the caller wrote none),
	// case-folded: the table names the caller can produce. A resolved object one of them names is the caller's
	// wherever it binds, so a trusted definition reading the same object does not make it the definition's.
	std::set<Table> caller_table_names;
};
// A written reference (catalog, schema, table; empty parts unwritten) names a resolved object when the table
// names agree and every written qualifier agrees with the object's. A two-part name is schema.table or
// catalog.table, as DuckDB resolves it. An unqualified name matches the same table name in any schema of any
// catalog: conservative on purpose, since a written name is attributed to the caller wherever it resolves.
bool NamesObject(const std::set<Table> &written, const std::string &catalog, const std::string &schema,
                 const std::string &table);
// What the private bind learned about origin, for the execution boundary. Trusted definitions (host views,
// macros, attached tables) are opaque to policy: what their bodies introduce is exempt from function policy
// and from table policy alike. The bound plan carries no scope, so the plan walk applies policy to what it
// can attribute to the caller. Functions: the text's names (BindingPolicy), the names the caller's own binders
// looked up (default-macro expansions of caller-written names included), and the implementations those select.
// Objects: the identities the caller's own binders retrieved, and the identities the caller's text names.
// Everything else in the plan came from a trusted definition.
struct Provenance {
	// Canonical function names the caller's binders retrieved from the catalog.
	Names caller_lookups;
	// Canonical function names the default macros the caller's text expands to introduce (list_count names
	// list_aggr without the caller writing it). With the text's own names, these are the names the caller can
	// produce; a trusted scalar-macro body sharing one of them does not make it the body's.
	Names caller_expansions;
	// Canonical function names host scalar-macro bodies introduce. Such a body binds in the caller's own binder,
	// so its names are recognized by name; a name the caller can also produce is checked as the caller's,
	// query-wide.
	Names trusted_names;
	// Table references host scalar-macro bodies write (default arguments included), as written components. A
	// scalar macro body binds in the caller's own binder, so the objects its subqueries read are recognized by
	// name, exactly as its functions are; an object the caller also names is the caller's, query-wide.
	std::set<Table> trusted_table_names;
	// Resolved table and view identities (case-folded) by attribution: retrieved by the caller's own binders
	// or named in the caller's text, and retrieved only by trusted definitions. An identity in both is the
	// caller's.
	std::set<Table> caller_objects, trusted_objects;
	// How many times the private bind's plan scans each base table, by identity, and each table function, by
	// name. The engine's plan for the same statement may scan no other source and none more often; a plan that
	// does diverged from the validated statement and is refused.
	std::map<Table, size_t> validated_scans;
	std::map<std::string, size_t> validated_function_scans;
	// No text and no private bind on record (a Prepare() pre-screen): nothing can be attributed, and blocks and
	// table policy alike are deferred to execution, which rebinds inside the query.
	bool unattributed = false;
	// The caller's text, or a default macro it expands to, can produce this name.
	bool CallerCanName(const BindingPolicy &binding, const std::string &name) const;
	bool Attributable(const BindingPolicy &binding, const std::string &name) const;
	// The caller's text names this object.
	bool CallerNamesObject(const BindingPolicy &binding, const std::string &catalog, const std::string &schema,
	                       const std::string &table) const;
	// A resolved object a plan scans is the caller's: the caller's binders retrieved it or the caller's text
	// names it. An identity only trusted definitions retrieved is theirs. One the private bind never retrieved
	// at all is the caller's too: it can only have come from a plan that diverged from the validated statement.
	bool ObjectAttributable(const BindingPolicy &binding, const std::string &catalog, const std::string &schema,
	                        const std::string &table) const;
};
// A resolved identity as the provenance sets hold it: every component case-folded.
Table ObjectKey(const std::string &catalog, const std::string &schema, const std::string &table);
// The qualified name DuckDB hands its replacement-scan callbacks (ReplacementScan::GetFullPath): the non-empty
// parts joined with dots. Case-folded here because caller_table_refs is matched by name, never by file identity.
std::string TableRefPath(const std::string &catalog, const std::string &schema, const std::string &table);
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
