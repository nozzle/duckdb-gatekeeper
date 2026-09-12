# API reference

`gatekeeper_validate(sql[, options])` returns:

```text
STRUCT(
  allowed BOOLEAN,
  code VARCHAR,
  violations VARCHAR[],
  error_type VARCHAR,
  error_message VARCHAR
)
```

Only `allowed = true` with `code = 'ok'` is success. Policy violations are sorted
and deduplicated; repeated blocked function calls include their occurrence count.
Parser diagnostics use `error_type` and `error_message`. Empty strings indicate
no diagnostic. Codes are `ok`, `forbidden`, `unsupported`, `parser`,
`invalid_input`, and `binding`. Binding errors include missing objects/columns and
reader errors encountered during resolution. Resource failures and unexpected internal errors may raise a
DuckDB error rather than produce a row; callers must treat these as rejection.

Unknown keys, duplicate keys, unexpected JSON types, empty name entries, and
inconsistent allowlist options produce `invalid_input`. Names containing `*`
are literal names; no wildcard matching is performed. The multiplication operator
can be blocked with `"blocked_functions":["*"]` without blocking other functions.

## Functions

| Option | Default | Semantics |
| --- | --- | --- |
| `check_functions` | `true` | Enable allowlist enforcement. False leaves blocklist enforcement active. |
| `use_default_functions` | `true` when checking functions | Include reviewed built-ins/operators and core-extension compute functions. |
| `allowed_functions` | `[]` | Add exact function names. |
| `blocked_functions` | `[]` | Reject exact function names, regardless of defaults/additions. |

Function names are ASCII case-folded. Policies match leaf names irrespective of
schema/catalog qualification; independent catalog policy still applies. Blocks
win in both allowlist and blocklist-only modes. `check_functions:false` implicitly
disables defaults unless explicitly set; explicitly enabling defaults or supplying
allowlist additions in that mode is an error.

```json
{"allowed_functions":["my_function"],"blocked_functions":["md5"]}
```

```json
{"use_default_functions":false,"allowed_functions":["sum","avg","+"]}
```

```json
{"check_functions":false,"blocked_functions":["read_parquet"]}
```

Defaults are maintained in `inventories/core.json` and per-extension files under
`inventories/extensions/`. Compute groups are compiled in; elevated and unreviewed
groups remain excluded. See [the inventory update workflow](../inventories/README.md). They do not load
extensions. Keyword forms such as CURRENT_DATE are not explicit function calls.

## Catalogs, schemas, tables

`resolve_objects` defaults to `true`. After caller-facing syntax checks pass,
Gatekeeper binds statements on the calling connection and checks retrieved table
catalog entries, including unqualified references and tables behind trusted views
and macros. No query plan is executed. Set it to `false` for syntax-only validation.

In resolved mode, `allowed_catalogs:[]` rejects every resolved physical table.
A table entry without `catalog` matches that schema/table in any resolved catalog;
use `allowed_catalogs` or a table-entry catalog to narrow it. Names are compared
with actual catalog entries. View names are not physical-table permissions:
underlying tables must pass. Explicit caller catalog qualifiers are also checked
before binding. The following qualification-specific rules describe syntax-only mode.

Trusted catalog code and attached tables can use internal readers regardless of
caller function policies. The logical table is the authorization boundary.
Tests cover attached DuckDB tables and Parquet-backed views; a live remote Iceberg
catalog has not yet been tested. Binding may perform I/O even when later rejected.

| Option | Omitted | Empty array |
| --- | --- | --- |
| `allowed_catalogs` | No restriction on explicit catalog names | Reject all explicit catalog-qualified references |
| `allowed_schemas` | No schema restriction | Reject all physical table references |
| `allowed_tables` | No table restriction | Reject all physical table references |

Catalog/schema/table names use exact case-sensitive string matching. This is
conservative compared with DuckDB's case-insensitive binding; match the spelling
used in submitted SQL. All configured policies intersect. Object policies do not
restrict functions by their schema: function policy is separate.

Table entries require nonempty `schema` and `table`, and optionally `catalog`:

```json
{
  "allowed_catalogs":["analytics"],
  "allowed_schemas":["reporting"],
  "allowed_tables":[
    {"catalog":"analytics","schema":"reporting","table":"orders"},
    {"schema":"reporting","table":"customers"}
  ]
}
```

An omitted table-entry catalog matches only references without explicit catalogs.
Allowed catalogs check explicit table, function, and SHOW qualifiers; missing
catalogs are not resolved against the execution connection. Unqualified physical
tables fail enabled schema/table policies. Schema-qualified CTE-like names are
physical references. Ordinary CTEs are visible only in their query and later CTE
declarations; recursive self-reference is permitted only in the recursive term.
CTEs cannot grant exemptions across statements or outside their scope.

SHOW requires an explicit allowed schema when schema policy is configured.
Schema-wide SHOW is denied whenever a table allowlist is configured. DESCRIBE and
SUMMARIZE with nested queries validate their physical references normally.

## Capabilities

| Option | Default | Semantics |
| --- | --- | --- |
| `allow_recursive_ctes` | `true` | Permit supported recursive CTEs. |
| `allow_table_functions` | `true` | Permit table functions that pass all other policies. |
| `allow_dynamic_sql` | `false` | Permit reviewed dynamic SQL/table lookup names, subject to function policy. |
| `allow_file_table_references` | `false` | Permit file-shaped physical table references. |

Dynamic SQL currently covers table use of `query`, `query_table`, and
`json_execute_serialized_sql`, and explicit `json_serialize_plan` calls. It is a
reviewed inventory, not recognition of arbitrary application executors. Disabling
the allowlist does not override this restriction.

File-shaped references include names with `/`, `\`, or `://`, and names ending
case-insensitively in `.parquet`, `.csv`, `.tsv`, `.json`, `.jsonl`, `.ndjson`, `.gz`,
`.zst`, or `.xlsx`. Quoted identifiers with those shapes are rejected too. Scoped
CTE references are exempt because they do not resolve to files. This is not a
complete replacement-scan detector: host-language objects and new formats require
separate controls. There is no wildcard interpretation of a filename.

DDL/DML and unknown AST structures are always rejected. No option enables writes.

## Direct readers

Explicit `read_parquet`, `read_csv`, and other reader calls are governed by function
policy. Their elevated classifications exclude them from defaults. Admitting a
reader delegates its resource access to the application; no local/remote argument
validation is performed. The former `reader_paths` option is rejected as unknown.
Trusted attached-table implementations may read backing files after their logical
catalog/schema/table identity is authorized. `allow_file_table_references` still
controls caller-written file-shaped table references separately.

## Limits

```json
{
  "limits": {
    "max_statements": 1,
    "max_ast_bytes": 8388608,
    "max_ast_nodes": 100000,
    "max_ast_depth": 512
  }
}
```

All values are positive integers. `max_statements` may increase to 1000. Other
defaults are hard ceilings and may only be lowered. Empty SQL is rejected. Options
JSON has a fixed 1 MiB ceiling. `max_ast_bytes` also bounds SQL text before parsing;
the serialized AST bound is checked after serialization. Node/depth budgets apply
to validation traversal, treating opaque literal/type metadata as data. These are
not engine execution budgets and do not bound the cost of parsing a pathological
query below the byte limit. Use server deadlines and process resource limits too.

## One-time database defaults

```sql
SELECT gatekeeper_configure('{"blocked_functions":["md5"],"limits":{"max_statements":2}}');
SELECT gatekeeper_validate('SELECT md5(''x'')', '{"blocked_functions":[]}');
```

`gatekeeper_configure(options VARCHAR)` returns true or raises a DuckDB error.
Invalid input does not consume the one-time slot; subsequent successful configuration
attempts are rejected. Concurrent attempts serialize and exactly one succeeds.
Submit a single-row bootstrap call. There is no reset command.

Defaults are shared across connections in one database instance and disappear when
it closes. They are not persisted or transactional. Validation uses a consistent
snapshot per input chunk. Prepared validation queries observe defaults at execution.

Omitted request fields inherit defaults. Present fields replace the whole value,
including lists and the entire `limits` object; missing limit members then use
built-in values. `check_functions:false` implicitly disables inherited allowlist
defaults/additions unless explicitly supplied. `check_functions:true` restores
built-in function defaults unless `use_default_functions` is supplied explicitly.
Overrides can relax restrictions: this is configuration convenience, not enforcement.
