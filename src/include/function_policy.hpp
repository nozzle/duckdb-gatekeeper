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
	                            "query",
	                            "query_table",
	                            "read_duckdb",
	                            "seq_scan",
	                            "truncate_duckdb_logs",
	                            "which_secret"};
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

inline std::string CanonicalFunction(std::string name) {
	name = Lower(std::move(name));
	// Explicit aliases reviewed in DuckDB's Parquet registration; no runtime discovery.
	if (name == "parquet_scan")
		return "read_parquet";
	if (name == "->>" || name == "json_extract_path_text")
		return "json_extract_string";
	if (name == "->" || name == "json_extract_path")
		return "json_extract";
	return name;
}

inline bool FunctionDenied(const Policy &policy, const std::string &name) {
	auto canonical = CanonicalFunction(name);
	if (NeverBindFunctions().count(Lower(name)) || NeverBindFunctions().count(canonical))
		return true;
	for (const auto &blocked : policy.blocked_functions)
		if (CanonicalFunction(blocked) == canonical)
			return true;
	return false;
}

bool FunctionAllowed(const Policy &policy, const std::string &name);
} // namespace gatekeeper
