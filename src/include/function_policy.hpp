#pragma once
#include "validator.hpp"

namespace gatekeeper {
// Explicit source-reviewed entries, not a prefix match. See docs/security.md.
inline const Names &NeverBindFunctions() {
	static const Names names = {"checkpoint",
	                            "currval",
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
	                            "force_checkpoint",
	                            "gatekeeper_configure",
	                            "json_execute_serialized_sql",
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
	                            "which_secret"};
	return names;
}

inline std::string CanonicalFunction(std::string name) {
	name = Lower(std::move(name));
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

inline const Names &BuiltinTypes() {
	// default_types.cpp BUILTIN_TYPES at the pinned revision. JSON/INET are extension types.
	static const Names names = {"decimal",      "dec",
	                            "numeric",      "time",
	                            "time_ns",      "date",
	                            "timestamp",    "datetime",
	                            "timestamp_us", "timestamp_ms",
	                            "timestamp_ns", "timestamp_s",
	                            "timestamptz",  "timestamp with time zone",
	                            "timetz",       "time with time zone",
	                            "interval",     "varchar",
	                            "bpchar",       "string",
	                            "char",         "nvarchar",
	                            "text",         "blob",
	                            "bytea",        "varbinary",
	                            "binary",       "hugeint",
	                            "int128",       "uhugeint",
	                            "uint128",      "bigint",
	                            "oid",          "long",
	                            "int8",         "int64",
	                            "ubigint",      "uint64",
	                            "integer",      "int",
	                            "int4",         "signed",
	                            "integral",     "int32",
	                            "uinteger",     "uint32",
	                            "smallint",     "int2",
	                            "short",        "int16",
	                            "usmallint",    "uint16",
	                            "tinyint",      "int1",
	                            "utinyint",     "uint8",
	                            "struct",       "row",
	                            "list",         "array",
	                            "map",          "union",
	                            "bit",          "bitstring",
	                            "variant",      "bignum",
	                            "varint",       "boolean",
	                            "bool",         "logical",
	                            "uuid",         "guid",
	                            "enum",         "null",
	                            "float",        "real",
	                            "float4",       "double",
	                            "float8",       "geometry",
	                            "type"};
	return names;
}
bool FunctionAllowed(const Policy &policy, const std::string &name);
bool TypeAllowed(const Policy &policy, const std::string &catalog, const std::string &schema, const std::string &name,
                 bool resolved);
} // namespace gatekeeper
