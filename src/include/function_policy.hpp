#pragma once
#include "validator.hpp"

namespace gatekeeper {
// Explicit source-reviewed entries, not a prefix match. See docs/security.md.
inline const Names &NeverBindFunctions() {
	static const Names names = {"checkpoint",
	                            "currval",
	                            "disable_logging",
	                            "duckdb_approx_database_count",
	                            "duckdb_columns",
	                            "duckdb_connection_count",
	                            "duckdb_constraints",
	                            "duckdb_coordinate_systems",
	                            "duckdb_databases",
	                            "duckdb_dependencies",
	                            "duckdb_extensions",
	                            "duckdb_external_file_cache",
	                            "duckdb_functions",
	                            "duckdb_indexes",
	                            "duckdb_log_contexts",
	                            "duckdb_logs",
	                            "duckdb_logs_parsed",
	                            "duckdb_memory",
	                            "duckdb_prepared_statements",
	                            "duckdb_profiling_settings",
	                            "duckdb_schemas",
	                            "duckdb_secret_types",
	                            "duckdb_secrets",
	                            "duckdb_sequences",
	                            "duckdb_settings",
	                            "duckdb_table_sample",
	                            "duckdb_tables",
	                            "duckdb_temporary_files",
	                            "duckdb_types",
	                            "duckdb_variables",
	                            "duckdb_views",
	                            "enable_logging",
	                            "force_checkpoint",
	                            "gatekeeper_configure",
	                            "gatekeeper_enforce",
	                            "json_execute_serialized_sql",
	                            "json_serialize_plan",
	                            "nextval",
	                            "pragma_collations",
	                            "pragma_database_size",
	                            "pragma_metadata_info",
	                            "pragma_show",
	                            "pragma_storage_info",
	                            "pragma_table_info",
	                            "pragma_table_sample",
	                            "quack_query",
	                            "quack_query_by_name",
	                            "query",
	                            "query_table",
	                            "read_duckdb",
	                            "seq_scan",
	                            "truncate_duckdb_logs",
	                            "which_secret",
	                            "write_log"};
	return names;
}

// Scalar functions that select a catalog aggregate by a caller-supplied name argument
// (extension/core_functions/scalar/list/list_aggregates.cpp). The AST walk records when the caller writes
// one so that the bound target is allowlisted, not merely unblocked; both sides must use the same names.
inline const Names &DispatchingAggregators() {
	static const Names names = {"aggregate", "array_aggr", "array_aggregate", "list_aggr", "list_aggregate"};
	return names;
}

// System builtins whose bind data is always ListLambdaBindData carrying the executable lambda body
// (list_transform.cpp, list_filter.cpp, list_reduce.cpp and their registered aliases in functions.json).
// Authorization must be able to walk that body; if it cannot, validation fails closed.
inline const Names &ListLambdaFunctions() {
	static const Names names = {"list_transform", "array_transform", "list_apply",   "array_apply",
	                            "apply",          "list_filter",     "array_filter", "filter",
	                            "list_reduce",    "array_reduce",    "reduce"};
	return names;
}

// 1.5 WindowExpression::WindowFunctions maps syntax directly to an expression kind;
// it does not select a second catalog entry. Used only to recover parsed provenance.
inline std::string WindowImplementationName(std::string name) {
	name = Lower(std::move(name));
	if (name == "rank_dense")
		return "dense_rank";
	if (name == "first" || name == "last")
		return name + "_value";
	return name;
}

bool SystemIdentity(const Identity &identity);

// Implementation substitutions, not policy aliases. These edges require an observed system entry.
// 1.5 uses the possible set conservatively; 2.0 checks an actual retained-definition edge.
// minmax.cpp BindMinMax, date_part.cpp DatePartBind, quantile.cpp DiscreteQuantile{List,}Function::Bind
// on both supported engines. No catalog discovery or arbitrary same-leaf host inference.
inline Names FunctionImplementations(const Identity &source, int engine_major) {
	Names names{Lower(source.name)};
	if (!SystemIdentity(source) || source.internal != true)
		return names;
	if (source.type == "aggregate") {
		if (source.name == "min")
			names.insert("arg_min");
		if (source.name == "max")
			names.insert("arg_max");
		if (source.name == "quantile")
			names.insert("quantile_disc");
	}
	if (source.type == "scalar" && (source.name == "date_part" || source.name == "datepart")) {
		names.insert("epoch");
		names.insert("julian");
		// 2.0 DatePartBind replaces every constant part. DatePartUnaryFunctionName
		// maps DOW/DOY and the plural micro/milliseconds to their registration names;
		// all remaining valid DatePartSpecifier values use the lowercase enum name.
		// 1.5 DatePartBind replaces only EPOCH and JULIAN_DAY.
		if (engine_major >= 2) {
			static const Names unary = {"year",          "month",          "day",         "decade", "century",
			                            "millennium",    "microsecond",    "millisecond", "second", "minute",
			                            "hour",          "dayofweek",      "isodow",      "week",   "isoyear",
			                            "quarter",       "dayofyear",      "yearweek",    "era",    "timezone",
			                            "timezone_hour", "timezone_minute"};
			names.insert(unary.begin(), unary.end());
		}
	}
	return names;
}

// The never-bind list: functions no policy can admit on any caller-authored route.
inline bool NeverBind(const std::string &name) { return NeverBindFunctions().count(Lower(name)); }

// Gatekeeper's own control plane: the policy and the lifecycle of the log that records its decisions. These
// are refused on every route, trusted definitions included. A host view or macro that exposed one would let
// a caller's SELECT rewrite the policy or erase its own record, which no definition legitimately intends;
// everything else a trusted definition uses is that definition's business.
inline const Names &ControlPlaneFunctions() {
	static const Names names = {"disable_logging",    "enable_logging",       "gatekeeper_configure",
	                            "gatekeeper_enforce", "truncate_duckdb_logs", "write_log"};
	return names;
}

inline bool ControlPlane(const std::string &name) { return ControlPlaneFunctions().count(Lower(name)); }

// The policy's explicit blocks. They govern names attributable to the caller: the caller's text, the
// implementations binding derives from it, and the readers its file paths choose. A host view, macro, or
// attached table is a trusted definition; nothing inside one is subject to blocks.
bool FunctionBlocked(const Policy &policy, const Identity &identity);

inline bool FunctionDenied(const Policy &policy, const Identity &identity) {
	return NeverBind(identity.name) || FunctionBlocked(policy, identity);
}

// Functions DuckDB binds for a collation (function.cpp: nocase, noaccent, nfc; the ICU extension registers
// icu_collate_<name> for each of its collations). A caller-written COLLATE chooses one without naming it.
inline bool CollationFunction(const std::string &name) {
	auto lower = Lower(name);
	return lower == "lower" || lower == "strip_accents" || lower == "nfc_normalize" ||
	       lower.compare(0, 12, "icu_collate_") == 0;
}

// Eligibility is only a pre-bind leaf screen, never a resolved authorization decision.
bool FunctionEligible(const Policy &policy, const std::string &name);
bool FunctionAllowed(const Policy &policy, const Identity &identity);
bool SystemIdentity(const Identity &identity);
bool SupportedFunctionKind(const std::string &kind);
} // namespace gatekeeper
