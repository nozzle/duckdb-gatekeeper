# Core classification correction (review wave 1)

Source of truth: DuckDB **1.5.5**, commit
[`d8cdaa33fda8df955cc76ef58a280f68f4cd43fa`](https://github.com/duckdb/duckdb/tree/d8cdaa33fda8df955cc76ef58a280f68f4cd43fa).
This is a correction of excluded-name review records, not a default expansion or
engine upgrade. The 864 compute defaults and accepted signature baseline stay intact.

## Reviewed capabilities

| Source paths under the pinned tree | Finding |
| --- | --- |
| `src/function/table/{read_csv,read_file,glob,sniff_csv,read_duckdb}.cpp` | CSV auto/manual readers, text/blob readers, globbing, CSV sniffing, and hidden read-only database attachment access external resources. Include scalar-path and list-path registrations. |
| `src/function/table/system/{pragma_storage_info,pragma_table_sample,duckdb_which_secret}.cpp` | Catalog lookup and physical storage/sample disclosure; secret selection via `SecretManager::LookupSecret`. |
| `src/function/table/query_function.cpp` | `query` reparses SQL and `query_table` resolves dynamic names, including list/by-name overloads. |
| `src/catalog/default/default_table_functions.cpp` | `histogram`/`histogram_values` table macros invoke `query_table`. The aggregate sharing the `histogram` name does not make that name compute-only. `duckdb_logs_parsed` and `duckdb_profiling_settings` expand to log/settings readers. |
| `extension/core_functions/scalar/list/list_aggregates.cpp`, `functions.json` | `aggregate`, `array_aggr`, `array_aggregate`, `list_aggr`, `list_aggregate` select and bind a system-catalog aggregate supplied as an argument. Fixed-name reviewed list macros are not equivalent to this caller-controlled dispatch. |
| `src/function/table/arrow.cpp` | `arrow_scan` and `arrow_scan_dumb` dereference host pointers and invoke external callbacks, including schema discovery during binding. |
| `src/function/table/system/duckdb_*.cpp` | The promoted names enumerate catalogs, connections, secrets, settings, variables, logs, prepared statements, storage/cache/memory state. `duckdb_coordinate_systems` scans catalog entries, not a static coordinate dataset. |
| `src/function/table/system/pragma_{collations,database_size,metadata_info,table_info,user_agent}.cpp` | Catalog/storage/configuration inspection; `pragma_show` shares the table-info implementation. |
| `src/function/table/checkpoint.cpp`, `src/function/scalar/sequence/nextval.cpp` | Checkpoint storage mutation, sequence advancement and sequence-state inspection. |
| `src/function/table/system/{logging_utils,enable_profiling}.cpp`, `src/function/scalar/system/write_log.cpp` | Logging/profiling mutation and output; optional destinations can be files. |
| `extension/core_functions/scalar/generic/{system_functions,current_setting}.cpp`, `src/function/scalar/generic/getvariable.cpp`, `src/function/scalar/system/current_*_id.cpp` | Session/search-path/configuration/transaction inspection. `current_setting` can autoload a configuration extension. |
| `extension/core_functions/scalar/date/current.cpp`, `scalar/random/{random,setseed}.cpp`, corresponding `functions.json` aliases | Transaction time, mutable RNG state and seed mutation. UUID aliases share their generators; UUIDv7 also encodes time. |
| `src/catalog/default/default_functions.cpp` | `ago`, `pg_conf_load_time`, `pg_postmaster_start_time` use current time; `current_catalog`, `format_type`, `get_block_size`, `pg_get_constraintdef`, `pg_get_viewdef` expand to metadata readers. |

Ten core names formerly appeared only in the MotherDuck elevated runtime snapshot:
`read_csv`, `read_csv_auto`, `read_text`, `read_blob`, `glob`, `sniff_csv`,
`read_duckdb`, `pragma_storage_info`, `duckdb_table_sample`, `which_secret`.
Their classification now lives in `core.json`; MotherDuck's binary provenance and
source-limited review caveats remain in its own notes.

## Retained limits

The original 185 unreviewed names were **not all dangerous**. For example,
`duckdb_keywords` reads parser keywords, `duckdb_optimizers` enumerates an embedded
optimizer list, and many PostgreSQL privilege/visibility compatibility macros
return constants. They remain excluded and unreviewed pending a separate compute
admission review; they are not relabeled elevated merely because of their names.
Unaudited internal helpers, Python-specific registrations, and other remaining
names also remain unreviewed. No runtime discovery was used to generate defaults.

The Python signature baseline includes statically linked and Python-only functions,
not every optional extension. This correction does not claim fresh source or
runtime coverage of proprietary MotherDuck or other optional extensions. No source
pins, signatures, or baseline acceptance were changed.
