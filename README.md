# Gatekeeper for DuckDB

[Security model](docs/security.md) · [Function inventories](inventories/README.md) · [Contributing](CONTRIBUTING.md)

A DuckDB extension that checks untrusted SQL against a policy before you run it.
Gatekeeper parses the statement, inspects the syntax and functions the caller wrote,
then binds it on your connection to authorize the actual tables and views it resolves
to, the functions the caller requested, and explicit blocks inside trusted
views and macros. The result is a native STRUCT with structured diagnostics.

- **864 reviewed function defaults**, plus exact-name allow and block lists.
- **Resolved catalog/schema/table/view authorization**, including unqualified names.
- **Read-only statements only**, with capability controls and AST limits.
- **A lockable global policy** that request options can narrow but never widen.

> Early development. Targets **DuckDB 1.5.5 only**; community publication is pending.
> Gatekeeper is a pre-execution validator, not a sandbox: read
> the [security model](docs/security.md) before integrating.

## Installation

**Pending publication:** the following commands will become available after Gatekeeper
is accepted and deployed in the DuckDB community repository. For now, use the
[build and local-load instructions](CONTRIBUTING.md#building).

```sql
INSTALL gatekeeper FROM community;
LOAD gatekeeper;
```

Community binaries are built and signed by DuckDB and load with signature verification
enabled. Source builds and binaries attached to this project's GitHub Releases are
unsigned development artifacts; see [loading unsigned builds](CONTRIBUTING.md#loading-unsigned-builds).

Gatekeeper supports exactly DuckDB **1.5.5**, including its reviewed source revision.
New DuckDB patch and minor releases require a coordinated review, rebuild, and community
descriptor update. Gatekeeper may be unavailable on a newer engine until that work lands.

**Browser/Wasm:** the EH bundle is supported with a pinned DuckDB-Wasm runtime
embedding DuckDB 1.5.5. See [Wasm installation and browser tests](test/wasm/README.md)
for building/loading the extension and the excluded MVP/threads targets.

## How it works

![Gatekeeper validation pipeline: untrusted SQL is parsed, the AST is checked, then the statement is bound on your connection and each resolved object is authorized against the global policy and request options before a result STRUCT is returned](docs/pipeline.svg)

Gatekeeper parses the statement, checks the syntax the caller wrote (functions,
capabilities, limits), then binds it on your connection and authorizes every table and
view it resolves to, plus the functions the caller requested. Functions that
trusted views and macros introduce internally are exempt from the caller allowlist but
still subject to explicit blocks and the never-bind list. Types, casts, and collations are trusted
as part of the host-configured database. Each check
runs against both the global policy and the request layer (global policy plus the
request's named options); both must allow the query. Nothing is executed, but **binding
can perform I/O** through trusted catalogs and explicitly admitted readers.

## Quickstart

```sql
CREATE SCHEMA reporting;
CREATE TABLE reporting.orders (customer_id INTEGER, amount DOUBLE);
INSERT INTO reporting.orders VALUES (1, 20), (1, 30), (2, 15);
```

```sql
SELECT gatekeeper_validate(
    'SELECT customer_id, sum(amount) FROM reporting.orders GROUP BY customer_id',
    allowed_tables := [{catalog: 'memory', schema: 'reporting', 'table': 'orders'}]
).allowed;
-- true
```

```sql
SELECT gatekeeper_validate('DROP TABLE reporting.orders').code;
-- unsupported
```

```sql
SELECT gatekeeper_validate('SELECT * FROM missing_table').code;
-- binding
```

Require `allowed = true` **and** `code = 'ok'`, treat exceptions and missing results as
denials, then execute the same SQL text on the same connection.

## Functions

```text
gatekeeper_validate(sql VARCHAR, option := value, ...)   -- returns the result STRUCT
CALL gatekeeper_configure(option := value, ...)          -- replaces the global policy
```

Options are named DuckDB values. Unknown or duplicate names and wrong types raise a
DuckDB error while the statement is bound, for both functions. Invalid runtime values
(`max_statements := 0`, a NULL list member) differ: `gatekeeper_validate` returns a
result with `code = 'invalid_input'`, while `CALL gatekeeper_configure` raises and
leaves the active policy unchanged. Both accept host-bound parameters (`?`, `$1`), so policies never need to be
spliced into SQL text.
For `CALL gatekeeper_configure`, an empty non-STRUCT list supplied to
`allowed_tables` means an empty restriction regardless of its
element type: DuckDB converts even an untyped `[]` to `INTEGER[]` before the
configuration callback. Nonempty lists require structs, and typed STRUCT lists
have their field names checked even when empty.

### Result

| Field | Type | Meaning |
| --- | --- | --- |
| `allowed` | BOOLEAN | True exactly when `code = 'ok'`. |
| `code` | VARCHAR | `ok`, `forbidden`, `unsupported`, `parser`, `binding`, `invalid_input`. |
| `violations` | STRUCT[] | `rule`, `message`, `catalog`, `schema`, `table`, `function_name`, `position`. Nonempty only for `forbidden`/`unsupported`. |
| `error_type` | VARCHAR | DuckDB exception category (`parser`, `Catalog`, `Binder`, ...) when one is available; may be empty for `invalid_input`. Always empty for `ok`/`forbidden`/`unsupported`. |
| `error_message` | VARCHAR | The engine's message for that error; empty for policy denials. |
| `position` | BIGINT | Zero-based parser byte offset, or NULL. |
| `objects` | STRUCT[] | Resolved `catalog`, `schema`, `table`, `type` (`table`/`view`) the query bound to. Empty unless `ok`. |
| `functions` | STRUCT[] | Resolved `catalog`, `schema`, `name`, `type` (`scalar`, `aggregate`, `table`, `macro`, `table_macro`, `pragma`, `window`). Empty unless `ok`. |

Violation `rule` values: `function`, `table`, `internal_object`,
`dynamic_sql`, `replacement_scan`,
`bind_time_expression`, `statement`, `limit`, `unsupported_structure`. Branch on these
fields, not on message text.

`objects` and `functions` are sorted, deduplicated binding evidence: views appear with
their underlying tables; CTE names do not. They help detect search-path surprises but do
not prove definitions are unchanged between validation and execution.

What the three failure shapes look like:

```jsonc
// Policy denial: code 'forbidden', structured violations, no error text.
// SELECT * FROM hr.salaries with allowed_tables := [{catalog:'*', schema:'reporting', 'table':'*'}]
{ "allowed": false, "code": "forbidden",
  "violations": [{ "rule": "table", "message": "object is not allowed",
                   "catalog": "memory", "schema": "hr", "table": "salaries",
                   "function_name": "", "position": null }],
  "error_type": "", "error_message": "", "position": null, "objects": [], "functions": [] }

// Function not in the defaults (md5 is; current_date is not).
// SELECT md5('x'), current_date
{ "allowed": false, "code": "forbidden",
  "violations": [{ "rule": "function", "message": "resolved function is not allowed: current_date",
                   "catalog": "", "schema": "", "table": "", "function_name": "current_date",
                   "position": null }],
  "error_type": "", "error_message": "", "position": null, "objects": [], "functions": [] }

// Engine error: code names the phase, violations are empty, the message is DuckDB's.
// SELECT * FROM missing_table
{ "allowed": false, "code": "binding", "violations": [],
  "error_type": "Catalog", "error_message": "Table with name missing_table does not exist!",
  "position": null, "objects": [], "functions": [] }
```

### Options

| Option | Type | Built-in default | Notes |
| --- | --- | --- | --- |
| `use_default_functions` | BOOLEAN | `true` | `true`: the 864 reviewed compute defaults **plus** `allowed_functions`. `false`: only `allowed_functions`. |
| `allowed_functions` | VARCHAR[] | `[]` | Exact leaf names, ASCII case-folded. `'*'` is multiplication, not a wildcard. |
| `blocked_functions` | VARCHAR[] | `[]` | Always wins, including inside trusted views and macros. |
| `allowed_tables` | STRUCT[] | unrestricted (non-internal) | `{catalog?, schema, table}`; `'*'` matches any complete component. Omitted/NULL catalog also matches any. `[]` denies all tables and views. |
| `allow_replacement_scans` | BOOLEAN | `false` | Let `SELECT * FROM 'x.parquet'` and other unresolved names fall through to DuckDB replacement scans. The resolved reader is then authorized like any table function. |
| `max_statements` | BIGINT | `1` | Positive; at most 1000. |

Function allowlisting always applies to caller-authored functions. With
`use_default_functions := true`, the allowed set is **defaults ∪ allowed_functions**;
with `false`, it is just `allowed_functions`. Explicit blocks and the never-bind list
win either way. Global and request policies each must grant permission: a request
cannot add a function that the global policy denies.

Recursive CTEs are supported and undergo the same function and table checks as other
queries. Fixed internal guardrails bound SQL input and serialized AST size to 8 MiB,
AST traversal to 100,000 nodes, and AST depth to 512. These are not configurable and
do not bound recursive iterations, execution time, memory, or result size. Parsing
and serialization precede the AST traversal checks; enforce resource budgets in the host.

Caller-written table functions (`FROM range(...)`, `FROM read_parquet(...)`) use
the same function policy as scalar and aggregate calls. Readers are not defaults;
admitting one permits its resource access, without path restrictions from
`allowed_tables`. Authorized trusted views and macros may introduce readers
internally, but explicit blocks and the never-bind list still apply.
To deny default row generators, add their names to `blocked_functions`, or set
`use_default_functions := false` with an explicit `allowed_functions` list.
Function policies apply by name, including scalar calls sharing that name.

```sql
SELECT gatekeeper_validate('SELECT md5(''hello'')', blocked_functions := ['md5']).allowed;
-- false
```

```sql
SELECT gatekeeper_validate('SELECT 1+2', use_default_functions := false, allowed_functions := ['+']).allowed;
-- true
```

### Table matching

Each `allowed_tables` rule matches all three components of a **resolved** table/view
identity; any matching rule grants access within that policy layer. Both global and
request layers must independently grant the object. Names are ASCII case-insensitive.
Only a whole-component `'*'` is special: `sales_*`, `?`, and `%` are literal names,
not glob/SQL patterns. There is no escape for a literal name consisting solely of `*`.
Wildcards include objects created or attached later and, for `catalog: '*'`, temporary
shadow tables. Prefer explicit catalog names when that scope is not intended.

```sql
SELECT gatekeeper_validate(
    'SELECT * FROM reporting.orders',
    allowed_tables := [{catalog: '*', schema: 'reporting', 'table': '*'}]
).allowed;
-- true
```

For catalog-wide access use `{catalog: 'warehouse', schema: '*', 'table': '*'}`.
Multiple entries can pair different catalogs and schemas without granting their
cross-product. Omit the option for unrestricted non-internal tables/views; supply
`[]` to deny them all. Omitted/NULL `catalog` is shorthand for any catalog.
Schema and table are required.

Internal objects require a matching rule with **exact schema and table names** in
each policy layer; catalog may match any. Broad wildcards never grant that opt-in.
Metadata readers remain on the never-bind list even with exact object permission.
Schema-wide `SHOW` is denied whenever a table restriction is configured, including
`*/*/*`; this option does not filter metadata rows. `DESCRIBE table` still checks the
resolved table normally.

Table rules neither grant nor restrict types/functions. Types are supplied by the
host without separate authorization. Functions use exact leaf-name policies, not
wildcards, and assume trusted catalog definitions.

Things that surprise people:

- Objects are authorized by their **resolved** identity after binding, using the caller's
  search path and transaction. Views and the tables behind them must both pass.
- Dynamic SQL (`query`, `query_table`, `json_execute_serialized_sql`, `json_serialize_plan`),
  internal metadata views (`duckdb_tables`, `information_schema.*`, `SHOW TABLES`), and
  sequence/storage functions are denied regardless of options; they are on the
  non-overridable [never-bind list](docs/security.md#never-bind-functions).
- `current_date`, `current_user`, and other session-value functions are **not** defaults.
  Grant them by resolved name in the global policy (`allowed_functions := ['current_date']`).
- Collations available on the connection (`COLLATE de`, `nocase`, etc.) need no
  Gatekeeper permission. Function policy still applies to explicit function calls
  and bound function implementations; there is no collation-specific allow/block check.
- Types need no Gatekeeper permission: JSON, INET, Spatial types, and user-defined
  types are available when DuckDB can resolve them. The database owner controls
  extension loading and type definitions. Table rules restrict table
  and view access, not type names. Expressions in type parameters still undergo
  the usual bind-time expression checks. Type resolution can autoload or autoinstall
  extensions when those settings are enabled; provision extensions during trusted
  setup and disable `autoload_known_extensions` and `autoinstall_known_extensions`
  on validation connections.
- `SELECT * FROM 'x.parquet'` needs `allow_replacement_scans := true` **and** the reader
  DuckDB substitutes admitted by name: `parquet_scan` for Parquet, `read_csv_auto` for
  CSV, `read_json_auto` for JSON. The decision happens before the reader binds, so a
  denied path is never opened. `objects` then lists the path with type `replacement`.
  Host-language scans (DataFrames, relations in scope) are always denied.
- Prepared parameters validate only when DuckDB can finish binding without values
  (`WHERE id = ?`, `LIMIT ?`, `$1::INTEGER`). Bare `SELECT $1` returns `binding`.
- Caller expressions in bind-time positions (LIMIT, reader arguments, type parameters,
  PIVOT values) must be literals or parameters; arithmetic there is rejected, including
  `range(1+2)`. The one exception is a **correlated** call to the system table-in-out
  functions `unnest`, `range`, or `generate_series`, whose arguments DuckDB evaluates per
  row at execution time: `FROM t, unnest(list_transform(t.arr, lambda x: x + 1))` is
  accepted, while the same call over a literal list is not.

## Global policy

```sql
CALL gatekeeper_configure(
    allowed_tables := [{catalog: 'memory', schema: 'reporting', 'table': '*'}],
    blocked_functions := ['md5']
);
-- true
```

```sql
SELECT gatekeeper_validate('SELECT md5(''hello'')', blocked_functions := []).allowed;
-- false: the request cannot clear a global block
```

```sql
SELECT current_setting('gatekeeper_policy').blocked_functions;
-- [md5]
```

The global policy is a ceiling. Each `CALL` **replaces** it atomically, starting from the
built-in defaults for any option you omit; an invalid call leaves the previous policy in
place. It is global-only: shared by every connection of the database instance, not
persisted, not undone by rollback, and `SET SESSION`/`RESET SESSION` are rejected.

| Dimension | How the layers combine |
| --- | --- |
| Blocks and the never-bind list | Either layer's deny wins. |
| Allowlists (functions, tables) | Each layer must allow the resolved identity. |
| Capability flags | Both layers must grant. |
| Statement limit | The stricter value applies. |

An otherwise valid request that tries to widen access does not error; it simply cannot
authorize anything the global policy denies. Invalid option values, such as
`max_statements := 0`, are rejected as `invalid_input`. Grant capabilities
(`read_parquet`, higher statement limits) in `CALL gatekeeper_configure`, and use
request options to narrow per tenant.

| Operation | SQL |
| --- | --- |
| Inspect | `SELECT current_setting('gatekeeper_policy')` |
| Reset to built-ins | `RESET gatekeeper_policy` (or `CALL gatekeeper_configure()`) |
| Freeze | `SET lock_configuration = true` after trusted setup |
| Allow later changes while locked | `SET allowed_configs = ['gatekeeper_policy']` before locking |

Prefer `CALL` for authoring: it validates option names, types, and nested identity fields
before DuckDB's casts, and fills omitted options from the built-in defaults.
`SET gatekeeper_policy = <STRUCT>` also works but requires the **complete canonical
STRUCT**: every option plus the `restrict_tables`
flag, with no NULL at any depth. `SET gatekeeper_policy = {max_statements: 2}` fails
with `NULL policy field: use_default_functions`; start from
`current_setting('gatekeeper_policy')` and `struct_update` it instead. DuckDB silently
drops unknown keys during the cast; the NULL-free canonical value (`catalog: ''` means
any catalog) means a typo that displaces a required field fails closed. Check the readback.
When setting `allowed_tables` directly, also set `restrict_tables := true`;
a nonempty list with `restrict_tables = false` is rejected. With an empty list,
`restrict_tables = true` denies all tables/views and `false` is unrestricted
for non-internal objects.
`gatekeeper_configure` itself is never admitted in validated SQL, including through views
or macros.

## Python

After community publication, the Python setup is:

```python
import duckdb

db = duckdb.connect()
db.execute("INSTALL gatekeeper FROM community")
db.execute("LOAD gatekeeper")
db.execute("CREATE SCHEMA reporting")
db.execute("CREATE TABLE reporting.orders AS SELECT 20.0 AS amount")

# Trusted setup: install the ceiling, then lock it.
tables = [{"catalog": "memory", "schema": "reporting", "table": "*"}]
db.execute("CALL gatekeeper_configure(allowed_tables := ?)", [tables])
db.execute("SET lock_configuration = true")

sql = "SELECT sum(amount) FROM reporting.orders"
decision = db.execute(
    "SELECT gatekeeper_validate(?, allowed_tables := ?)", [sql, tables]
).fetchone()[0]
if not decision["allowed"] or decision["code"] != "ok":
    raise PermissionError(decision["violations"] or decision["error_message"])
rows = db.execute(sql).fetchall()
```

Until publication, replace the connection and install/load lines with the
[unsigned build setup](CONTRIBUTING.md#loading-unsigned-builds).

Recommended validating-connection settings (`autoload_known_extensions = false`, memory
and thread limits, `lock_configuration`) are in the
[security model](docs/security.md#validating-connection-profiles).

## Limitations

Gatekeeper authorizes what a statement references; it does not filter rows or columns,
enforce execution deadlines or memory budgets, or isolate the filesystem and network.
Binding may perform I/O before a denial is returned. Function defaults are a reviewed
name inventory, not a proof that every overload is harmless. The full list of boundaries
is in [docs/security.md](docs/security.md#remaining-boundaries).

## License

[MIT](LICENSE). See [NOTICE](NOTICE) for provenance and third-party requirements.
