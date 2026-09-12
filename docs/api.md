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
```

Only `allowed = true` and `code = 'ok'` indicate success. Codes are `ok`,
`forbidden`, `unsupported`, `parser`, `binding`, and `invalid_input`. Rule identifiers
include `function`, `catalog`, `schema`, `table`, `dynamic_sql`, `table_function`,
`recursive_cte`, `file_table`, `replacement_scan`, `statement`, `limit`, and
`unsupported_structure`. Consumers should use these fields rather than parse messages.
Repeated function violations include occurrence counts in the message. Absent object
identifiers are empty strings. Positions are zero-based parser byte offsets when
available, otherwise NULL; resolved-object positions may be unavailable.

Resource and unexpected execution errors can raise exceptions instead of returning
a result. Callers must reject exceptions, NULL/missing results, and unknown codes.

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
| `allowed_tables` | STRUCT[] | Unrestricted objects | Deny tables and views |

Table structs require nonempty `schema` and `table` strings; optional `catalog` may
be omitted or NULL. An omitted catalog matches that schema/name in any catalog.
No wildcard or dotted-string parsing is performed. Unknown table fields are invalid.
Use `allowed_catalogs` or explicit entry catalogs to constrain cross-catalog access.

```sql
SELECT gatekeeper_validate(
  'SELECT * FROM reporting.orders',
  allowed_schemas := ['reporting'],
  allowed_tables := [{schema: 'reporting', 'table': 'orders'}]
);
```

Object names compare exactly, case-sensitively, against resolved catalog identities.
Caller-provided catalog qualifiers are checked before binding too. Missing catalog
or schema qualifiers are resolved using the caller's search path and transaction.

**Views and their underlying tables must both pass.** A file-backed view with no
physical table callbacks must still be explicitly authorized by its own identity.
Trusted view/macro and attached-table implementation functions are not subjected
to caller-facing function policies again. Attached Iceberg/DuckLake tables are
authorized at their logical catalog/schema/table identity, not their backing files.

Explicit admitted table functions are capabilities, not catalog table permissions;
an empty `allowed_tables` does not prohibit `range()`. Dynamic lookup functions,
when explicitly enabled and admitted, must still pass catalog callbacks for objects
they resolve. Host-language/implicit replacement scans are rejected because their
identity is not a trustworthy catalog object. Prefer explicit admitted readers or
trusted catalog objects. This includes file replacements even if the syntactic
file-reference flag is enabled; that flag alone cannot grant resolved authorization.

Schema-wide SHOW is rejected with a table policy. SHOW/DESCRIBE may also involve
system views, which must pass object policy. This API does not filter metadata rows.

## Capability options

| Option | Type | Default |
| --- | --- | --- |
| `allow_recursive_ctes` | BOOLEAN | true |
| `allow_table_functions` | BOOLEAN | true |
| `allow_dynamic_sql` | BOOLEAN | false |
| `allow_file_table_references` | BOOLEAN | false |

Permissions intersect: allowing a function does not override capability restrictions.
Dynamic SQL covers table calls to `query`, `query_table`, and
`json_execute_serialized_sql`, plus explicit `json_serialize_plan` calls. This is a
reviewed inventory, not recognition of arbitrary application functions.

File-shaped names contain `/`, `\`, or `://`, or end in `.parquet`, `.csv`, `.tsv`,
`.json`, `.jsonl`, `.ndjson`, `.gz`, `.zst`, or `.xlsx` (case-insensitively). Quoted
physical object names with those shapes also require opt-in. Scoped CTE references
are exempt. DDL/DML and unsupported AST structures are always rejected.

## Limits

Limits are independent named integer arguments; omitted ones inherit defaults.

| Option | Default / maximum |
| --- | --- |
| `max_statements` | 1 / 1000 |
| `max_ast_bytes` | 8388608 |
| `max_ast_nodes` | 100000 |
| `max_ast_depth` | 512 |

Values must be positive integers. Floating-point/boolean values are not coerced.
Empty SQL is rejected. AST bytes also bound SQL input before parsing. Serialization
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
