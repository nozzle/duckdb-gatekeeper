# API reference

```sql
gatekeeper_validate(sql VARCHAR, option := value, ...)
gatekeeper_configure(option := value, ...)
```

Options are named, native DuckDB values, not JSON. Unknown names, duplicate names,
unnamed options, and incompatible types raise binder errors. Runtime invalid values
and NULL validation inputs return `invalid_input`. Configuration errors raise a
DuckDB error. There is no `resolve_objects` option or public syntax-only function.
All successful validation includes binding on the calling connection.

## Result

Validation returns a STRUCT:

```text
allowed BOOLEAN
code VARCHAR
violations STRUCT(
  rule VARCHAR, message VARCHAR, catalog VARCHAR, schema VARCHAR,
  table VARCHAR, function_name VARCHAR, position BIGINT
)[]
error_type VARCHAR
error_message VARCHAR
position BIGINT
objects STRUCT(catalog VARCHAR, schema VARCHAR, table VARCHAR, type VARCHAR)[]
functions STRUCT(catalog VARCHAR, schema VARCHAR, name VARCHAR, type VARCHAR)[]
```

Only `allowed = true` and `code = 'ok'` indicate success. Codes are `ok`,
`forbidden`, `unsupported`, `parser`, `binding`, and `invalid_input`. Rule identifiers
include `function`, `catalog`, `schema`, `table`, `dynamic_sql`, `table_function`,
`recursive_cte`, `file_table`, `replacement_scan`, `internal_object`, `type`, `statement`, `limit`,
`bind_time_expression`, and `unsupported_structure`. Consumers should use these fields rather than parse messages.
`allowed` is true exactly when `code` is `ok`. Successful results have empty
violations and error messages. `forbidden`/`unsupported` have nonempty violations
and an empty error message; `parser`/`binding`/`invalid_input` have empty violations
and a nonempty error message.
Repeated function violations include occurrence counts in the message. Absent object
identifiers are empty strings. Positions are zero-based parser byte offsets when
available, otherwise NULL; resolved-object positions may be unavailable.

`objects` and `functions` contain sorted, deduplicated **observed binding dependencies**
only on success; both are empty for every other result, including errors after partial
binding. Sorting is lexicographic by `(catalog, schema, table/name, type)` using the
reported spelling. Object types are `table`/`view`; function types are `scalar`,
`aggregate`, `table`, `macro`, `table_macro`, `pragma`, or `window`. Catalog lookups
preserve separate resolved identifiers, including `system.main`; dots in names are
never parsed as separators. Views and their underlying tables appear; CTE names do not.
Function implementations observed only in a bound plan may have empty catalog/schema
when no matching name/kind was observed by the catalog callback; these empty fields
mean unknown provenance, not the default catalog. This is neither an exhaustive
execution trace nor overload/definition identity. Comparing dependencies can detect
some search-path differences but cannot close TOCTOU or detect same-name replacements.

## Prepared parameters

`?`, `$1`, and `$name` use UNKNOWN-typed binder placeholders with no supplied values.
Validation succeeds only when DuckDB completes binding, for example a typed table
predicate, `LIMIT ?`, or `SELECT $1::INTEGER`. Bare `SELECT $1`, ambiguous overloads
such as `abs($1)`, and value-dependent reader arguments return `binding` when values
or types are required. No dummy values are substituted, and partial plans are never
approved. Parameter values, value-dependent behavior, and execution-time rebinds
are not validated; execute the same text with trusted parameter handling and reject
binding failures rather than inlining untrusted values.

## Bind-time expressions

No opt-out is provided for the `bind_time_expression` rule. Caller expressions in
LIMIT/OFFSET (including percentage limits), AT clauses, table-function arguments,
COLUMNS selectors, PIVOT IN values, quantile fractions/options, UNNEST options, and
type parameters must be literals or parameters that DuckDB can bind without values.
Type parameters can also contain nested type syntax. In list-capable positions,
literal lists/structs are supported; PIVOT accepts literal tuples and unqualified
label names. TRUE/FALSE parser casts are accepted, but arbitrary casts, arithmetic,
function calls, subqueries and COLUMNS lambdas are rejected in these positions.
The pinned parser stores sample sizes as literal values (and only accepts literal
percentage-limit syntax); those forms remain supported. Literal constructors must
resolve to system scalar entries, so a same-named macro cannot evade the restriction.

These are conservative caller-syntax checks, not a resource budget or complete
interception of bind-time execution. Trusted views/macros, function-specific binders,
large literals, type binders, parsing and serialization still require host limits.

Resource and unexpected execution errors can raise exceptions instead of returning
a result. Callers must reject exceptions, NULL/missing results, and unknown codes.
Cancellation, internal, fatal, and out-of-memory engine exceptions propagate to
DuckDB. Parser exceptions return `parser`; other engine errors before binding return
`invalid_input`, and during binding return `binding`. Parsing uses the connection's parser options, and AST serialization
uses the latest format of the pinned engine regardless of its storage build flags.

## Function options

| Option | Type | Built-in default |
| --- | --- | --- |
| `check_functions` | BOOLEAN | true |
| `use_default_functions` | BOOLEAN | true when allowlisting |
| `allowed_functions` | VARCHAR[] | [] |
| `blocked_functions` | VARCHAR[] | [] |

Defaults contain the reviewed compute inventories. `allowed_functions` adds exact
names; `blocked_functions` wins over defaults and additions in all modes. Functions
are ASCII case-folded by leaf name. `*` is the literal multiplication operator, not
a wildcard. Empty names, embedded NULs, and NULL list members are invalid.
Explicit blocks also apply to resolved functions inside views and macros. JSON
arrows/path aliases share canonical extraction blocks (`json_extract` and
`json_extract_string`). The [never-bind list](security.md#never-bind-functions)
is non-overridable, even with `check_functions := false`.

Syntax-generated functions also require permission: list construction/slicing are
checked before binding; indexing, field extraction and SQL-value names are checked
against the implementation selected by DuckDB. Actual qualified columns remain
columns. A query-wide conservative check also applies to matching implementations
inside trusted expansions; see [the enforcement boundary](security.md#function-enforcement-and-trusted-expansion).
For example, under `use_default_functions := false`, `SELECT * FROM v_st` can
pass while `SELECT t.x FROM t, v_st` fails if the trusted view uses `struct_extract`
and that name is not admitted. Single-part whole-row references (`SELECT t FROM t`)
also require `struct_pack`, so ordinary column references conservatively enable
that implementation check query-wide.

**Compatibility:** bare `CURRENT_DATE`, `CURRENT_TIMESTAMP`, `CURRENT_TIME`,
`LOCALTIME`, `LOCALTIMESTAMP`, and other SQL-value functions now follow their inventory
classification. Current-time/session functions are denied by default; opt in using
their resolved names, e.g. `allowed_functions := ['current_date']` (timestamp/time use
`get_current_timestamp`/`get_current_time`, local forms use `current_localtime`/
`current_localtimestamp`). Casts `::JSON` and `::INET` require `allowed_types`.

```sql
SELECT gatekeeper_validate('SELECT md5(''x'')', blocked_functions := ['md5']);
SELECT gatekeeper_validate('SELECT 1+2', use_default_functions := false, allowed_functions := ['+']);
SELECT gatekeeper_validate('SELECT 1', check_functions := false, blocked_functions := ['read_parquet']);
```

Turning off `check_functions` implicitly disables inherited allowlist defaults and
additions unless explicitly supplied; conflicting explicit allowlist options fail.
Turning it on restores built-in defaults unless `use_default_functions` is specified.
Explicit readers are governed by function policy; admitting a reader permits its
resource access, not an argument-level sandbox. Inventories live in
[`inventories/`](../inventories/README.md) and do not load extensions.

## Object options

| Option | Type | Omitted | [] |
| --- | --- | --- | --- |
| `allowed_catalogs` | VARCHAR[] | Unrestricted catalogs | Deny catalog objects |
| `allowed_schemas` | VARCHAR[] | Unrestricted schemas | Deny schema objects |
| `allowed_tables` | STRUCT[] | Unrestricted non-internal objects | Deny tables and views |
| `allowed_types` | STRUCT[] | Built-in types only | Built-in types only (removes inherited entries) |

Table structs require nonempty `schema` and `table` strings; optional `catalog` may
be omitted or NULL. An omitted catalog matches that schema/name in any catalog.
`allowed_types` structs use `schema` and `type` with the same optional `catalog`; see
[Types and collations](#types-and-collations).
This includes `temp`: a temporary table can shadow a persistent table with the same
schema/name. Use explicit catalogs when that distinction matters, and inspect `objects`.
No wildcard or dotted-string parsing is performed. Unknown table fields are invalid.
Use `allowed_catalogs` or explicit entry catalogs to constrain cross-catalog access.

```sql
SELECT gatekeeper_validate(
  'SELECT * FROM reporting.orders',
  allowed_schemas := ['reporting'],
  allowed_tables := [{schema: 'reporting', 'table': 'orders'}]
);
```

Object names compare using ASCII case-folding against resolved catalog identities,
matching DuckDB identifier semantics. Diagnostics preserve the resolved spelling.
Caller-provided catalog qualifiers are checked before binding too. Missing catalog
or schema qualifiers are resolved using the caller's search path and transaction.

**Views and their underlying tables must both pass.** A file-backed view with no
physical table callbacks must still be explicitly authorized by its own identity.
Trusted view/macro and attached-table implementation functions pass explicit blocks
and never-bind checks, while retaining their caller-allowlist exemption (subject to
the syntax-overlap restriction above). Attached Iceberg/DuckLake tables are
authorized at their logical catalog/schema/table identity, not their backing files.
Caller CTEs can shadow table references inside trusted table macros because DuckDB
uses regular child binders there. Views use view binders and do not inherit that CTE
scope. The observed `objects` list reflects the actual binding; do not assume a
trusted table macro necessarily accesses its definition-time table.

Internal tables/views require explicit `allowed_tables` permission even when object
options are omitted. A schema allowlist alone does not admit system metadata views
such as `duckdb_tables`, `duckdb_views`, `sqlite_master`, or `information_schema.tables`.
An explicit entry satisfies object policy only: metadata views such as `duckdb_tables`
still fail the never-bind layer when expanded to their underlying metadata functions.
The standard internal metadata views cannot be admitted by object opt-in;
`internal_object` provides an earlier diagnostic, not an escape from never-bind.
Omitting the catalog in an explicit entry retains any-catalog matching.
This also applies transitively: a trusted user view over `duckdb_tables` requires
explicit permission for both the user view and that internal dependency.

Explicit admitted table functions are capabilities, not catalog table permissions;
an empty `allowed_tables` does not prohibit `range()`. Dynamic lookup functions in
the never-bind list cannot be admitted. Host-language/implicit replacement scans are rejected because their
identity is not a trustworthy catalog object. Prefer explicit admitted readers or
trusted catalog objects. This includes file replacements even if the syntactic
file-reference flag is enabled; that flag alone cannot grant resolved authorization.

Schema-wide SHOW is rejected with a table policy. SHOW/DESCRIBE may also involve
system views, which must pass object policy. In particular, `SHOW TABLES [FROM x]`
and `SHOW ALL TABLES` depend on internal metadata views and are denied by default.
A schema allowlist is insufficient, and adding an `allowed_tables` list also
triggers the schema-wide SHOW preflight denial. Their underlying metadata readers
are also never-bind functions. Use host-controlled metadata access outside validation
when needed. This API does not filter metadata rows.

## Types and collations

`allowed_types` is a list of structs requiring nonempty `schema` and `type`, with
optional `catalog` (omitted/NULL matches any catalog). Identifiers are ASCII-case-folded.
Omitted options inherit defaults; `[]` removes additional type permissions. Built-in
DuckDB types and their nested constructors remain available. Extension/user-defined
types—including JSON and INET—require explicit entries:

```sql
SELECT gatekeeper_validate('SELECT ''{}''::JSON',
    allowed_types := [{catalog: 'system', schema: 'main', type: 'json'}]);
```

Preflight inspects latest serialized type expressions and nested parameters; resolved
identities must match. Computed type parameters, computed type expressions and named
PIVOT enums are unsupported. Admitted nonbuiltin types also intersect `allowed_catalogs`
and `allowed_schemas`; JSON in `system.main` requires that namespace if those lists
are set. Built-in types remain exempt from namespace restrictions. The same type
name occurring in a trusted expansion
can be subject to this query-wide resolved check. Unknown fields, NULL entries and
invalid identifier values are rejected like `allowed_tables`.
Admitting an enum type also permits eligible default functions such as
`enum_range(NULL::your_enum)` to disclose its labels. `allowed_tables` is not an
enum-label or column-data policy; types use their separate permission rules.

Collations `binary` (also `c`/`posix`), `nocase`, `noaccent`, and `nfc` are available
by default. Other collation components require explicit `allowed_functions` entries,
as a separate binding capability. Disabling function checks does not grant collation
permission; because `allowed_functions` conflicts with `check_functions := false`,
enable function checks to admit a nondefault collation. This avoids broadening type/
collation lookup capabilities through the function-check toggle. Blocks win, including blocks on known built-in
implementation functions. Dotted combinations are checked component by component.
Disable autoload/autoinstall on validation connections; preflight and post-lookup
callbacks are not a guarantee against extension loading.

## Capability options

| Option | Type | Default |
| --- | --- | --- |
| `allow_recursive_ctes` | BOOLEAN | true |
| `allow_table_functions` | BOOLEAN | true |
| `allow_dynamic_sql` | BOOLEAN | false |
| `allow_file_table_references` | BOOLEAN | false; opt-in for real catalog objects with file-shaped names, not replacement-scan authorization |

Permissions intersect: allowing a function does not override capability restrictions.
Dynamic SQL covers table calls to `query`, `query_table`, and
`json_execute_serialized_sql`, plus explicit `json_serialize_plan` calls. This is a
reviewed inventory, not recognition of arbitrary application functions.
The never-bind functions `query`, `query_table` and `json_execute_serialized_sql`
remain denied even if this flag and explicit function permission are supplied.
`allow_dynamic_sql` is deprecated and retained for option compatibility; it no longer
admits SQL execution. It still gates the explicitly admitted plan-inspection function
`json_serialize_plan`.
The complete non-overridable [never-bind list](security.md#never-bind-functions)
includes metadata readers and sequence/storage operations; `allowed_functions`
cannot override it.

File-shaped names contain `/`, `\`, or `://`, or end in `.parquet`, `.csv`, `.tsv`,
`.json`, `.jsonl`, `.ndjson`, `.gz`, `.zst`, `.xlsx`, `.db`, `.ddb`, `.duckdb`, `.avro`,
`.shp`, `.gpkg`, or `.fgb` (case-insensitively). Each suffix followed by `?` anywhere
in the name is also caught, covering DuckDB's query/glob-marker forms. Both the leaf
name and DuckDB's dot-joined nonempty catalog/schema/table parts are checked, so
unquoted `data.csv` and `catalog.data.csv` receive the same preflight rejection. Quoted
physical object names with those shapes also require opt-in. Scoped CTE references
are exempt only when unqualified. DDL/DML and unsupported AST structures are always rejected.
The preflight deliberately also rejects real catalog tables named `csv`, `json`,
`db`, or another recognized suffix when qualified (for example, `main.csv`).
Quoting the identifiers does not change this; an unqualified `csv` is not file-shaped.
Use `allow_file_table_references := true` for such trusted objects; resolved-object
authorization still applies.

Replacement scans are collected during binding and rejected afterward, not before
their bind callbacks. This preflight filename inventory stops the reviewed forms
by default, but other dotted names can still cause filesystem existence probes and
custom replacements can still perform I/O before rejection. This is a syntactic
guard, not replacement-scan suppression (tracked in issue #3).
Enabling `allow_file_table_references` permits that pre-rejection binding work even
for known file-shaped names. It never makes an implicit file scan valid; use an
explicit admitted reader for file access. Shared connection configuration is not
temporarily modified by this scalar function.

## Limits

Limits are independent named integer arguments; omitted ones inherit defaults.

| Option | Default / maximum |
| --- | --- |
| `max_statements` | 1 / 1000 |
| `max_ast_bytes` | 8388608 |
| `max_ast_nodes` | 100000 |
| `max_ast_depth` | 512 |

Values must be positive integers. Floating-point/boolean values are not coerced.
Empty/comment-only SQL returns `invalid_input` with `SQL contains no statements`.
AST bytes also bound SQL input before parsing. Serialization
and binder work occur before some limits can be checked; these are not execution
budgets or a complete resource-exhaustion defense. Limit violations use `forbidden`
with rule `limit`, separate from unsupported syntax.

## Database defaults and parameters

```sql
SELECT gatekeeper_configure(blocked_functions := ['md5'], max_statements := 2);
SELECT gatekeeper_validate('SELECT md5(''x'')', blocked_functions := []);
```

Configuration is one-time per database instance, shared across connections, not
durable or transactional. There is no reset; invalid configuration leaves the slot
available. Request lists replace configured lists; each limit overrides independently.
Defaults may be relaxed by requests, so the application must control who supplies them.

Prepared arguments and per-row options are supported:

```python
decision = db.execute(
    "SELECT gatekeeper_validate(?, allowed_schemas := ?, blocked_functions := ?)",
    [sql, ["reporting"], ["md5"]],
).fetchone()[0]
```

Options are decoded directly from DuckDB values; no JSON encoding or unescaping is
performed. Binder errors for malformed API calls are distinct from a `binding`
result describing invalid submitted SQL.
