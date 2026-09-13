# Gatekeeper for DuckDB

[Security model](docs/security.md) · [Function inventories](inventories/README.md) · [Contributing](CONTRIBUTING.md)

A DuckDB extension that checks untrusted SQL against a policy before you run it.
Gatekeeper parses the statement, inspects the syntax and functions the caller wrote,
then binds it on your connection to authorize the actual tables and views it resolves
to, the types and functions the caller requested, and explicit blocks inside trusted
views and macros. The result is a native STRUCT with structured diagnostics.

- **864 reviewed function defaults**, plus exact-name allow and block lists.
- **Resolved catalog/schema/table/view authorization**, including unqualified names.
- **Read-only statements only**, with type, collation, and capability controls and AST limits.
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
view it resolves to, plus the types and functions the caller requested. Functions that
trusted views and macros introduce internally are exempt from the caller allowlist but
still subject to explicit blocks and the never-bind list; types they introduce internally
are not caller capabilities and are not checked. Each check
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
    allowed_schemas := ['reporting'],
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

Violation `rule` values: `function`, `catalog`, `schema`, `table`, `type`, `internal_object`,
`dynamic_sql`, `table_function`, `recursive_cte`, `replacement_scan`,
`bind_time_expression`, `statement`, `limit`, `unsupported_structure`. Branch on these
fields, not on message text.

`objects` and `functions` are sorted, deduplicated binding evidence: views appear with
their underlying tables; CTE names do not. They help detect search-path surprises but do
not prove definitions are unchanged between validation and execution.

What the three failure shapes look like:

```jsonc
// Policy denial: code 'forbidden', structured violations, no error text.
// SELECT * FROM hr.salaries   with   allowed_schemas := ['reporting']
{ "allowed": false, "code": "forbidden",
  "violations": [{ "rule": "schema", "message": "schema is not allowed",
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
| `check_functions` | BOOLEAN | `true` | `false` skips the allowlist; blocks and the never-bind list still apply. |
| `use_default_functions` | BOOLEAN | `true` | Admit the 864 reviewed compute functions. |
| `allowed_functions` | VARCHAR[] | `[]` | Exact leaf names, ASCII case-folded. `'*'` is multiplication, not a wildcard. |
| `blocked_functions` | VARCHAR[] | `[]` | Always wins, including inside trusted views and macros. |
| `allowed_catalogs` | VARCHAR[] | unrestricted | `[]` denies every catalog object. |
| `allowed_schemas` | VARCHAR[] | unrestricted | `[]` denies every schema object. |
| `allowed_tables` | STRUCT[] | unrestricted (non-internal) | `{catalog?, schema, table}`; omitted catalog matches any. `[]` denies all tables and views. |
| `allowed_types` | STRUCT[] | built-in types only | `{catalog?, schema, type}`. Extension and user types (JSON, INET, enums) need an entry. |
| `allow_recursive_ctes` | BOOLEAN | `true` | |
| `allow_table_functions` | BOOLEAN | `true` | Table functions are still subject to function policy. |
| `allow_replacement_scans` | BOOLEAN | `false` | Let `SELECT * FROM 'x.parquet'` and other unresolved names fall through to DuckDB replacement scans. The resolved reader is then authorized like any table function. |
| `max_statements` | BIGINT | `1` | Positive; at most 1000. |
| `max_ast_bytes` | BIGINT | `8388608` | Positive; at most the default. Also bounds the input text. |
| `max_ast_nodes` | BIGINT | `100000` | Positive; at most the default. |
| `max_ast_depth` | BIGINT | `512` | Positive; at most the default. |

```sql
SELECT gatekeeper_validate('SELECT md5(''hello'')', blocked_functions := ['md5']).allowed;
-- false
```

```sql
SELECT gatekeeper_validate('SELECT 1+2', use_default_functions := false, allowed_functions := ['+']).allowed;
-- true
```

Things that surprise people:

- Objects are authorized by their **resolved** identity after binding, using the caller's
  search path and transaction. Views and the tables behind them must both pass.
- Dynamic SQL (`query`, `query_table`, `json_execute_serialized_sql`, `json_serialize_plan`),
  internal metadata views (`duckdb_tables`, `information_schema.*`, `SHOW TABLES`), and
  sequence/storage functions are denied regardless of options; they are on the
  non-overridable [never-bind list](docs/security.md#never-bind-functions).
- `current_date`, `current_user`, and other session-value functions are **not** defaults.
  Grant them by resolved name in the global policy (`allowed_functions := ['current_date']`).
- Collations `binary`/`c`/`posix`, `nocase`, `noaccent`, and `nfc` are available by default
  and still honor `blocked_functions`. Any other collation (`COLLATE de`) needs its name in
  `allowed_functions` with `check_functions` on.
- Extension types need a matching `allowed_types` entry per type: `::JSON` needs
  `{catalog: 'system', schema: 'main', type: 'json'}`, `::INET` needs
  `{catalog: 'system', schema: 'main', type: 'inet'}` and the `inet` extension loaded
  first. A `json` entry does not admit `inet`.
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
CALL gatekeeper_configure(allowed_schemas := ['reporting'], blocked_functions := ['md5']);
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
| Allowlists (functions, catalogs, schemas, tables, types) | Each layer must allow the resolved identity. |
| Capability flags | Both layers must grant. |
| Limits | The stricter value applies. |

An otherwise valid request that tries to widen access does not error; it simply cannot
authorize anything the global policy denies. Conflicting options are still rejected as
`invalid_input`, for example `check_functions := false` with a nonempty
`allowed_functions := ['md5']` (an empty list or `use_default_functions := false` is
compatible with disabled checks). So grant capabilities (`read_parquet`, custom types, higher
statement limits) in `CALL gatekeeper_configure`, and use request options to narrow per
tenant.

| Operation | SQL |
| --- | --- |
| Inspect | `SELECT current_setting('gatekeeper_policy')` |
| Reset to built-ins | `RESET gatekeeper_policy` (or `CALL gatekeeper_configure()`) |
| Freeze | `SET lock_configuration = true` after trusted setup |
| Allow later changes while locked | `SET allowed_configs = ['gatekeeper_policy']` before locking |

Prefer `CALL` for authoring: it validates option names, types, and nested identity fields
before DuckDB's casts, and fills omitted options from the built-in defaults.
`SET gatekeeper_policy = <STRUCT>` also works but requires the **complete canonical
STRUCT**: every option plus the `restrict_catalogs`/`restrict_schemas`/`restrict_tables`
flags, with no NULL at any depth. `SET gatekeeper_policy = {max_statements: 2}` fails
with `NULL policy field: check_functions`; start from
`current_setting('gatekeeper_policy')` and `struct_update` it instead. DuckDB silently
drops unknown keys during the cast; the NULL-free canonical value (`catalog: ''` means
any catalog) means a typo that displaces a required field fails closed. Check the readback.
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
db.execute("CALL gatekeeper_configure(allowed_schemas := ?)", [["reporting"]])
db.execute("SET lock_configuration = true")

sql = "SELECT sum(amount) FROM reporting.orders"
decision = db.execute(
    "SELECT gatekeeper_validate(?, allowed_schemas := ?)", [sql, ["reporting"]]
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
