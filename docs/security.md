# Security model

Gatekeeper is a pre-execution validator, not an enforcement hook or a
database sandbox. A successful decision means the SQL conforms to the selected
syntax, caller-function and resolved-deny/object policies on the pinned parser/binder. It does not mean the SQL is cheap,
returns nonsensitive data, or cannot have side effects through admitted functions.

## Integrating

1. Load a trusted extension build and keep the execution catalog/search path trusted.
   Provision required extensions first, then set `autoload_known_extensions=false`
   and `autoinstall_known_extensions=false` on validation connections. Gatekeeper
   does not temporarily mutate those settings.
2. Install the global policy through trusted `CALL gatekeeper_configure`, then lock
   configuration. Construct any further request restrictions from authenticated context.
3. Run `SELECT * FROM gatekeeper_validate(?)` with the exact SQL to execute.
4. Require an explicit successful result; reject missing results, NULLs, and exceptions.
5. Execute the same SQL under controlled database/process settings.

`CALL gatekeeper_configure` atomically replaces a database-scoped authorization ceiling.
Request overrides can only narrow it: both policy layers must authorize the query,
and either layer's blocks win. Only trusted bootstrap should configure the instance.
After setup, `SET lock_configuration=true` blocks configuration through `CALL`, `SET`,
and `RESET`, unless the host deliberately exempts `gatekeeper_policy` in `allowed_configs`.
This protects Gatekeeper's policy, not arbitrary SQL execution: the application must
still require validation and control access to the raw connection/native APIs.
Configuration is nontransactional; a surrounding rollback does not undo replacement.
Each validation call takes one coherent snapshot at execution. Lock before exposing the instance.
Use strict parameterized `CALL` for authoring; direct STRUCT `SET` silently drops
unknown extra keys at any depth during DuckDB casting. The canonical setting is
NULL-free, so a typo that displaces a canonical field (a missing or NULL-filled nested
`catalog`, `schema`, or leaf) fails closed instead of widening catalog matching.
See [global policy](../README.md#global-policy) in the README.

Validation returns one row with `allowed`, `code`, `violations`, `error_type`,
`error_message`, `position`, `objects`, and `functions` as named columns. Require
`allowed = true` and `code = 'ok'`. The diagnostic/dependency lists retain nested
STRUCT elements. SQL text and options accept constant expressions or host-bound
parameters, not correlated/lateral per-row expressions. For multiple SQL strings,
make separate parameterized calls. Prepared executions read the current policy and
bind the submitted SQL again; preparing a call does not cache an authorization decision.
Validation also rejects non-null placeholder plans with unresolved parameter types;
otherwise execution could rebind to an implementation the validator never authorized.

Use `SELECT allowed FROM gatekeeper_validate(...)` to select an individual column,
or select `*` for all result columns.
Empty option lists are accepted regardless of element type, since DuckDB resolves
untyped `[]` to `INTEGER[]` before table binding. All-NULL lists also pass the element-type
check regardless of declared type (`[NULL]` and `[NULL]::DOUBLE[]` both return `invalid_input`
at execution). Lists with non-NULL members require the documented element types.
Nested identity fields are preserved
and checked, including the field names of typed empty STRUCT lists.

Tables and views are unrestricted until a layer configures `allowed_tables`; only
internal objects (`duckdb_*`, `information_schema.*`) need an explicit rule from the
start. Set `allowed_tables` in the global policy during trusted setup when tenants must
not see every table; `[]` denies all tables and views.
`allowed_tables` is a union of catalog/schema/table rules within each layer, with
an intersection between layers. A whole-component `*` matches any identifier;
other text is exact and ASCII case-folded. Matching uses resolved identities, not
caller spellings or CTE names. Wildcards cover future objects as well as existing
ones. `blocked_tables` uses the same matching rules, defaults to no blocks, and
works independently of the allowlist. A matching block in either layer always wins,
including on underlying tables/views introduced by trusted views and macros.
Blocks match resolved objects, not CTE names or reader paths/arguments.
Internal objects require exact schema/table names in a matching allow rule; a
wildcard catalog is permitted. Block wildcards also match internal objects, even
when an exact allow rule exists. Metadata readers remain independently forbidden,
and schema-wide `SHOW` is denied under any configured table restriction.
Table rules do not restrict or authorize function/type namespaces. Functions use
leaf-name policies; types are supplied by the host without separate authorization;
see [table ACL](../README.md#table-acl).

## Function enforcement and trusted expansion

Caller-authored function names pass the AST allowlist. Unambiguous syntax such as
list construction and slicing adds `list_value`/`array_slice` to that check.
Ambiguous indexing, dotted references, arrows and SQL-value names record the possible
implementations; the catalog callback checks the implementation DuckDB actually
selects. `t.column` and a real column named `current_schema` are not automatically
treated as functions. `->>` and JSON path aliases share canonical extraction blocks.

Function allowlisting cannot be disabled. Each policy layer admits its explicit
`allowed_functions` plus the reviewed defaults when `use_default_functions` is true;
explicit blocks and the never-bind list always take precedence.

The Parquet reader names `read_parquet` and `parquet_scan` share allow/block
permission. This explicit pair is source-reviewed in
`duckdb/extension/parquet/parquet_extension.cpp` (`LoadInternal` registers the same
`ParquetScanFunction::GetFunctionSet()` under both names). There is no dynamic alias
discovery. CSV/JSON reader names are not grouped. Parquet violations use the canonical
name `read_parquet`; successful dependency lists retain observed function names.

The callback applies explicit blocks and the non-overridable never-bind list below
to scalar, aggregate, table, macro, table-macro and pragma-function entries, including
trusted expansions. Authorized views backed by `read_parquet` still work unless
that reader is blocked. The callback exposes no expression origin or reliable
macro/view boundary: when caller syntax requires an implementation check, a trusted
expansion using the same implementation must also pass it. This conservative
query-wide restriction can deny a mixed caller/view expression; it does not grant
an exception to caller code. Type names, casts, and collations are trusted host
database configuration and are not authorized separately.
Name-selected aggregate dispatch (`list_aggregate`, `list_aggr`, `aggregate`,
`array_aggregate`, `array_aggr`) is elevated, and admitting a dispatcher does not admit
every aggregate it can reach: when the caller writes one, the aggregate DuckDB resolves
from the caller's (foldable) name argument must pass both allowlists, and like other
ambiguous caller syntax the check applies query-wide, so a trusted view's own dispatch in
the same plan is checked too. Dispatchers used only inside trusted definitions, and the
fixed `histogram` behind `list_distinct`/`list_unique`, keep the block-only treatment.

Defaults are admitted by leaf name, so a host-created macro or function that shadows a
default name is a trusted definition: `CREATE MACRO ltrim(x) AS ...` in a schema ahead of
`system` on the search path is admitted whenever `ltrim` is, and its body is checked
against blocks and the never-bind list only. The same holds for views, types, casts, and
collations. Gatekeeper assumes catalog integrity; letting untrusted users create
definitions in a shared catalog is outside its model, and restricting defaults to
`system.main` would not by itself make such DDL safe.
Concretely, with defaults disabled, `SELECT * FROM v_st` may pass but
`SELECT t.x FROM t, v_st` may fail because the view uses `struct_extract`. Whole-row
`SELECT t FROM t` needs `struct_pack`; single-part references therefore enable its
query-wide check too. Single-arrow function-child `x -> ...` remains ambiguous: DuckDB
can fall back to JSON binding even inside a function argument. Such syntax retains
the conservative `json_extract` candidate. Use `lambda x: ...` to avoid that ambiguity
when combining lambdas with trusted JSON expansions.

### Never-bind functions

The explicit list in `src/include/function_policy.hpp` contains:

```
checkpoint currval force_checkpoint nextval gatekeeper_configure
query query_table json_execute_serialized_sql json_serialize_plan read_duckdb seq_scan which_secret
pragma_collations pragma_database_size pragma_metadata_info pragma_show
pragma_storage_info pragma_table_info pragma_table_sample
duckdb_approx_database_count duckdb_columns duckdb_connection_count duckdb_constraints
duckdb_coordinate_systems duckdb_databases duckdb_dependencies duckdb_extensions
duckdb_external_file_cache duckdb_functions duckdb_indexes duckdb_log_contexts
duckdb_logs duckdb_logs_parsed duckdb_memory duckdb_prepared_statements
duckdb_profiling_settings duckdb_schemas duckdb_secret_types duckdb_secrets
duckdb_sequences duckdb_settings duckdb_table_sample duckdb_tables
duckdb_temporary_files duckdb_types duckdb_variables duckdb_views
```

Source review at the pinned revision: `src/function/table/query_function.cpp`
reparses dynamic SQL/names; `read_duckdb.cpp` attaches hidden databases;
`src/function/table/system/` readers inspect catalogs, secrets, storage or session
state outside table authorization; `checkpoint.cpp` and `scalar/sequence/nextval.cpp`
mutate or inspect storage/sequence state. `seq_scan` is the internal scan entry,
not a caller capability (normal physical scans retain object authorization).
`gatekeeper_configure` mutates the global policy and is always forbidden in submitted
SQL, including resolved table-function uses inside trusted views/macros.
JSON SQL execution is defined in `extension/json/`. `pragma_table_sample` is a
reserved defensive spelling; the pinned registration is `duckdb_table_sample`.
Static `duckdb_keywords`/`duckdb_optimizers` are deliberately not prefix-denied.
All listed names are excluded from defaults and cannot be admitted by options.
Metadata views expanding to these readers are denied even with `allowed_tables`.
This is deliberate: metadata readers enumerate across catalogs and cannot be row-
filtered by object callbacks. Tenant introspection must use a host-controlled API.
`json_serialize_plan` is listed because it binds and plans caller-supplied SQL at
execution time, outside this validation.

### Callback bypasses

Gatekeeper does not restrict type or collation names, or authorize cast implementations.
The database owner controls extension loading and definitions. Table/view catalog
and schema restrictions do not restrict type lookup. There is no mandatory type audit.
Type resolution can autoload or autoinstall extensions when enabled; hosts must
provision extensions during trusted setup and disable `autoload_known_extensions`
and `autoinstall_known_extensions` on validation connections.
Built-in temporal casts can use ICU timezone/calendar settings; GEOMETRY CRS binding
can consult trusted CRS providers and `ignore_unknown_crs`.

- `bind_pivot.cpp` performs direct aggregate and enum lookups. Explicit aggregate
  names pass preflight; named PIVOT enums use the host's type definitions.
- `bind_window_expression.cpp` and `function_binder.cpp` contain direct aggregate/
  function lookup paths. Caller names pass preflight; surviving bound scalar,
  aggregate, window and table functions also pass a resolved-deny plan walk.
- `collation_binding.cpp` directly loads collation entries and binds their scalar
  functions. Collation names and inferred implementations are not checked in preflight.
  The generic resolved-function deny walk still applies to surviving bound functions,
  including implementations introduced by collations; it is not a collation policy.
- The plan walk cannot undo bind-time work or see functions already folded away.
  Host default collations, trusted extension callbacks, custom casts/type binders,
  macro expansion internals and optimizer rewrites are not a complete execution
  interception surface. In particular, global blocks are not a sandbox for arbitrary
  trusted callback code that performs its own direct lookups/evaluation.

The bound-plan authorization module also checks SELECT-list `UNNEST`, executable
list lambda bodies (including collation implementations inside them), and list
aggregate implementations such as `sum` inside `list_sum`. DuckDB stores lambdas
and list aggregates in function bind data rather than ordinary expression children.
Lambda bodies are walked directly; the private list-aggregate bind data is inspected
through its pinned serialization callback, without evaluating or rebinding arguments.
Both list-aggregate serialization and fixed histogram inspection require the bound
function's `system.main` provenance. Same-named scalar implementations from other
catalogs/schemas fail closed before their serialization callbacks can run.
`list_distinct`/`list_unique` and their `array_*` aliases use the source-reviewed fixed
`histogram` implementation.
These implementations obey blocks in both layers and appear in successful function
evidence. Their catalog/schema are empty when the bound representation supplies no
reliable provenance. Arbitrary extension bind data is not introspected.

## Remaining boundaries

- Validation always binds on the calling connection and authorizes retrieved table
  and view identities, including underlying objects from views/macros. No public
  syntax-only mode exists. Function matching remains name-based, not a proof of a
  macro/UDF's implementation; catalog integrity is assumed.
- Trusted catalog code and attached tables may invoke elevated readers internally.
  Backing-file reads for an authorized logical table are allowed. Binder callbacks
  identify tables without depending on a particular scan operator. Local Iceberg
  REST/MinIO and DuckLake integration tests verify this boundary; other catalog
  implementations still need verification.
- Binding may perform remote I/O or evaluate bind-time expressions before returning,
  even for a request eventually denied. Caller-authored prohibited functions are
  rejected first; trusted expansions pass the resolved deny layer, not a wholesale
  caller allowlist. Lookup-triggered autoload can occur before the callback; use
  the host settings above, even for names included in the default inventories.
- No row/column authorization or execution-time memory/time/result limits.
- Default functions are a reviewed name inventory, not a proof of harmlessness for
  every overload or argument. Existing DuckDB implementations are trusted across
  engine upgrades; the inventory is not an exact-version compatibility gate. New
  names remain excluded until classified or explicitly allowed. The inventory admits the clock (`now`,
  `current_date`, `uuidv7`), non-cryptographic PRNG state including `setseed`'s reseed of
  the connection-local engine, and the host's `TimeZone`/`Calendar` settings that ICU
  temporal functions consume; results using them are not reproducible from SQL text
  alone, and a host that caches or replays tenant queries must account for that. All
  other catalog, session, configuration, or planner state is opt-in; see
  [inventories/README.md](../inventories/README.md#classification-criteria).
- Replacement scans are decided by a Gatekeeper callback installed first in DuckDB's
  replacement-scan list. It runs only while a validation is binding on the calling
  thread; ordinary connections are unaffected. Other callbacks only construct a table
  reference, so a denial happens before the substituted reader binds and no file is
  opened. Readers substituted by DuckDB are authorized by their resolved names
  (`parquet_scan`, `read_csv_auto`, `read_json_auto`), with `parquet_scan` sharing
  permission with `read_parquet`. No separate replacement-scan toggle exists.
  Host-language scans that resolve to subqueries are always denied. When no callback
  claims a name, Gatekeeper raises the engine's missing-table error itself rather than
  returning to DuckDB's loop, so host callbacks are invoked exactly once per lookup and
  only behind this authorization; DuckDB's autoload retry and `FileExists` probe do not
  run. If a catalog without transactional DDL finds the object on that lookup, the
  validation fails closed with a `binding` retry error rather than resuming the loop. The callback is keyed to the validating connection and nested validations
  restore the outer scope, so reentrant host callbacks cannot disable interception.
  Catalog objects with file-shaped names use ordinary object policy; unclaimed
  names return binding errors without file-name heuristics.
- Direct readers are controlled by function policy. There is no reader-argument
  inventory or local/remote path policy; admitting a reader permits its resource
  access. Resolved bindings do not provide an argument-level sandbox.
- Explicitly admitting eligible elevated readers transfers responsibility
  for their resources and trusted implementation to the application. The never-bind
  list cannot be overridden by any option.
- A fixed internal cap rejects multiple statements before binding with code `forbidden`
  and violation rule `limit`; empty or comment-only SQL returns `invalid_input`.
- Fixed internal limits cap SQL input and serialized AST size at 8 MiB, AST traversal
  at 100,000 nodes, and AST depth at 512. AST validation occurs after parsing and
  serialization; traversal limits do not replace process limits against
  parser/serializer resource exhaustion.
- Engine diagnostics are returned verbatim in `error_message` for `parser` and `binding`
  results. DuckDB's messages can name catalog objects (`Did you mean "secrets"?`), file
  paths, and reader arguments, including objects the policy denies. Policy denials
  (`forbidden`, `unsupported`) carry no engine text. Treat `error_message` as sensitive:
  log it for operators and return a generic error to untrusted callers. Trimming the
  message is not a reliable confidentiality boundary, because names can appear on any line.

Keep external access, extension loading, credentials, filesystem/network permissions,
and configuration changes controlled independently.

## Validating-connection profiles

Provision extensions, trusted catalogs/credentials, and Gatekeeper defaults before
locking configuration. Keep `search_path`, `USE`, attached catalog identities,
relevant parser settings, and trusted definitions aligned with execution. In-memory
and temporary objects belong to their connection/database context; a separate
validator cannot assume identical names refer to identical objects.

For a local-only deployment, after trusted setup:

```sql
SET enable_external_access=false;
SET autoload_known_extensions=false;
SET autoinstall_known_extensions=false;
SET memory_limit='512MB';
SET threads=1;
SET search_path='memory.reporting';
CALL gatekeeper_configure(allowed_tables := [{catalog: 'memory', schema: 'reporting', 'table': '*'}]);
SET lock_configuration=true;
```

For trusted Iceberg/DuckLake or reader-backed views, keep external access enabled
where required. Install/load extensions and attach catalogs through trusted bootstrap,
scope credentials and network/filesystem access outside DuckDB, then disable autoload
and autoinstall, choose an application-appropriate memory limit, set `threads=1`, align
the search path, and finally lock configuration. Gatekeeper never changes these host
settings on behalf of a query. Test the profile against the particular catalog.

`memory_limit` is not a hard process RSS bound; use process/container memory limits,
timeouts/cancellation and isolation for hostile input. Literal-only preflight prevents
the reviewed computed-expression forms at LIMIT/OFFSET, table-function arguments,
AT, COLUMNS, PIVOT, quantile fractions, UNNEST options and type parameters. It does
not cap literal sizes beyond AST/input limits or prevent all evaluation inside trusted
definitions and function/type binders. No runtime-discovered allowlist is introduced.

Successful dependency lists are useful audit evidence, not a TOCTOU solution. They
record observed lookups and surviving function implementations, may omit hidden
extension work, and do not hash definitions or identify overloads. Failed decisions
return empty lists to avoid presenting an incomplete dependency set as authorization.
Omitted/NULL catalogs and `catalog: '*'` in `allowed_tables` include `temp` shadow tables. Table macros may
inherit caller CTEs whereas views do not; compare actual resolved objects rather than
assuming definition-time bindings. User-defined enum types can expose all their labels
via `enum_range`, even when no table is read; type definitions are host-trusted data.

## Compatibility and review

Release binaries target DuckDB 1.5.5. Source builds may use another engine checkout;
the grammar and serializer come from that checkout, and DuckDB enforces binary
compatibility through the extension footer. That footer check can be disabled with
`allow_extensions_metadata_mismatch`, so Gatekeeper also records the engine it was built
from (the version tag for releases, the source id for dev builds, mirroring DuckDB's own
footer identity) and refuses to load into any other engine. The stamp is a single string
(`strings gatekeeper.duckdb_extension | grep GATEKEEPER_BUILD_ENGINE`). The host's identity
is read from its catalog (`pragma_version()`) rather than `DuckDB::LibraryVersion()`:
distributed loadables statically link their own DuckDB copy, so the latter only ever
reports the build engine. A grammar generated from one engine must never validate
statements for another. Gatekeeper also compiles DuckDB's in-tree JSON serializer
(`extension/json/json_serializer.cpp`) and uses internal binder entry points
(`Binder::CreateBinder`, `SetBindingMode`, `SetCatalogLookupCallback`,
`GetReplacementScans`) and bind-data serialization callbacks; none of these are stable
public API, so an engine upgrade can require source changes. Compatibility is therefore
checked by compilation and functional regressions on every candidate engine
(`compatibility.yml`), through both the direct CMake path and the community `make release`
path. Existing function classifications do not
need repeating for each engine version. Unknown serialized fields and
node classes fail closed. Cast types use latest `UNBOUND(TypeExpression)` decoding,
including nested type parameters. Computed type parameters remain conservatively
unsupported. Ordinary literal payloads remain data, not executable nodes.
The local tests and randomized-input checks are not a complete security audit.
DuckDB builds and signs binaries distributed through its community repository;
Gatekeeper's community publication is pending. Local builds, CI artifacts, and this
project's GitHub Release binaries are unsigned. Distribution signatures authenticate
the distributed binary, not its policy semantics or suitability for hostile workloads.
Platform CI, browser tests, and fuzzing provide regression coverage; production use
against hostile callers still requires review of the application and its trust boundary.
Suspected authorization bypasses should be reported privately as described in
[SECURITY.md](../SECURITY.md).

## Adversarial regression coverage

`test_redteam.py` checks nested table references in filters, windows, LIMIT/ORDER BY,
CTEs, views and macros; search-path and temporary-table shadowing; dynamic SQL;
write-containing batches; duplicate typed policy fields; fixed limits; and prepared
validation after catalog/policy changes. `test_global_policy.py` checks locking,
atomic replacement, strict configuration, and non-bypassable policy layers.
`test_adversarial_generated.py` combines nested queries and function
spellings deterministically and checks single-row NULL/allow/deny results and prepared executions.

DuckDB can wrap policy exceptions while binding a table macro. Such denials retain
`forbidden`, and all exception exits explicitly clear `allowed` so successful
preflight cannot leak into an error
result. Tests cover this independently of the error's DuckDB exception type.

Gatekeeper's AST and bound-expression walks use explicit work stacks. The AST walk
checks node and depth budgets. DuckDB parsing/serialization still has its own stack behavior.

The Python-wheel sanitizer runner uses AddressSanitizer and UndefinedBehaviorSanitizer
to instrument Gatekeeper and its compiled JsonSerializer. The Python DuckDB engine
and bundled yyjson library are not sanitizer-instrumented. Leak detection and vptr
checks are disabled for this mixed-runtime setup. This is regression testing,
not coverage-guided fuzzing or a full engine memory-safety audit.
Run `.venv/bin/python scripts/test_sanitized.py` for the instrumented suite.

The linked SQL/typed-option fuzz target exercises the public entry point against
fixed local catalog fixtures on every PR and main push, with an additional weekly run.
Its deterministic startup checks cover native policy setters and reentrant/stateful
replacement callbacks. Gatekeeper uses coverage and ASan/UBSan instrumentation;
the linked DuckDB engine is exercised but not fully instrumented. The macOS
Python-wheel sanitizer runner also disables libc++ container annotations because
containers cross instrumented and uninstrumented code. This is qualified
mixed-runtime coverage, not a whole-engine clean sanitizer bill.
