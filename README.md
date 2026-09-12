# Gatekeeper for DuckDB

[API reference](docs/api.md) · [Security model](docs/security.md) · [Function inventories](inventories/README.md)

A DuckDB extension for checking SQL against a configurable policy before running it.
Gatekeeper parses the query, checks its functions and syntax, and binds references
to authorize the actual tables it uses. The result is a native DuckDB STRUCT with
an allow/deny decision and diagnostics.

With Gatekeeper, you can:

- Start with **864 reviewed function names**, then add or block exact names.
- Restrict access by **catalog, schema, and table**, including unqualified references
  and underlying tables in views and macros.
- Reject DDL/DML, dynamic SQL, file-shaped table references, and unsupported syntax.
- Set statement-count and AST limits, or disable recursive CTEs and table functions.
- Configure database-wide defaults once and override individual options per request.

> **Status:** early development, targeting **DuckDB 1.5.5 only**. Gatekeeper is not
> published in the community repository yet. Local builds have been tested on macOS
> arm64; see [validation evidence](docs/validation-review.md) for clean-build and
> integration results. Wildcard matching and
> DuckDB v2 support are out of scope.

## Installation

[Build from source](#building-from-source), then start DuckDB 1.5.5 with unsigned
extension loading enabled for the local development artifact:

```sh
duckdb -unsigned
```

Load the extension using its absolute path:

```sql
LOAD '/absolute/path/to/duckdb-gatekeeper/build/release/extension/gatekeeper/gatekeeper.duckdb_extension';
```

Signed packages and `INSTALL gatekeeper FROM community` are not available yet.

## Quickstart

Create some application-owned data through trusted initialization:

```sql
CREATE SCHEMA reporting;
CREATE TABLE reporting.orders (customer_id INTEGER, amount DOUBLE);
INSERT INTO reporting.orders VALUES (1, 20), (1, 30), (2, 15);
```

Validate a query using the built-in defaults:

```sql
SELECT gatekeeper_validate(
    'SELECT customer_id, sum(amount) FROM reporting.orders GROUP BY customer_id'
) AS decision;
```

The decision contains:

```text
allowed:       true
code:          ok
violations:    []
error_type:    ""
error_message: ""
```

You can project individual fields directly in SQL:

```sql
SELECT gatekeeper_validate('DROP TABLE reporting.orders').allowed AS allowed;
-- false
```

```sql
SELECT gatekeeper_validate('SELECT * FROM missing_table').code AS code;
-- binding
```

Validation does not execute the submitted query plan. **Your application must check
the decision and execute the same SQL only when it succeeds.** Binding can read
metadata or perform I/O, so validation is not guaranteed to be side-effect-free.

## Configuring a policy

The optional second argument is a JSON object. By default the reviewed function
allowlist is enabled, one supported read statement is permitted, dynamic SQL and
file-shaped table references are disabled, and object references are resolved.
Physical tables are unrestricted unless you supply an object policy.

### Restrict tables

```sql
SELECT gatekeeper_validate(
    'SELECT sum(amount) FROM reporting.orders',
    '{
      "allowed_schemas": ["reporting"],
      "allowed_tables": [{"schema":"reporting","table":"orders"}],
      "allow_recursive_ctes": false,
      "allow_table_functions": false
    }'
).allowed AS allowed;
-- true
```

All configured policies must pass. With binding enabled, an omitted catalog in a
table entry matches that schema/table in any resolved catalog. Add an explicit
catalog or `allowed_catalogs` to narrow it. Empty object lists deny matching object
access; they do not mean unrestricted.

### Customize functions

`allowed_functions` adds names to the reviewed defaults. `blocked_functions` wins
over defaults and additions:

```sql
SELECT gatekeeper_validate(
    'SELECT md5(''hello'')',
    '{"blocked_functions":["md5"]}'
).violations AS violations;
-- ['function is not allowed: md5']
```

For an exact-only allowlist:

```json
{"use_default_functions":false,"allowed_functions":["sum","avg","+"]}
```

For blocklist-only checking:

```json
{"check_functions":false,"blocked_functions":["read_parquet"]}
```

Names are matched exactly, with ASCII case-folding for function names. **There are
no wildcards:** `"*"` names the multiplication operator. Admitting a reader such as
`read_parquet` permits that function's resource access; there is no local/remote
argument policy.

### Set database defaults once

Run this during trusted bootstrap:

```sql
SELECT gatekeeper_configure('{
  "allowed_schemas": ["reporting"],
  "blocked_functions": ["md5"]
}');
```

Connections in the same DuckDB instance share the defaults. A second configuration
attempt fails. Defaults are in-memory, not persisted or rolled back with transactions.

A request can replace a configured value:

```sql
SELECT gatekeeper_validate(
    'SELECT md5(''hello'')',
    '{"blocked_functions":[]}'
).allowed AS allowed;
-- true
```

Overrides **replace**, rather than append to, inherited lists and the entire
`limits` object. They may relax restrictions. Defaults are a convenience, not an
immutable security boundary: the application must control request options.

### Inspect SQL without binding

For offline checks where referenced tables do not exist:

```sql
SELECT gatekeeper_validate(
    'SELECT sum(amount) FROM reporting.future_orders',
    '{"resolve_objects":false}'
).allowed AS allowed;
-- true
```

Syntax-only mode cannot check resolved objects or dependencies hidden in views and
macros. See the [API reference](docs/api.md) for its qualification rules.

## Using Gatekeeper from Python

This example uses a locally built, unsigned extension and trusted setup data:

```python
import json
import duckdb

db = duckdb.connect(config={"allow_unsigned_extensions": "true"})
db.execute("LOAD '/absolute/path/to/gatekeeper.duckdb_extension'")
db.execute("CREATE SCHEMA reporting")
db.execute("CREATE TABLE reporting.orders AS SELECT 20.0 AS amount")

sql = "SELECT sum(amount) FROM reporting.orders"
options = {"allowed_schemas": ["reporting"]}
decision = db.execute(
    "SELECT gatekeeper_validate(?, ?)", [sql, json.dumps(options)]
).fetchone()[0]

if not decision["allowed"] or decision["code"] != "ok":
    raise ValueError(decision)

rows = db.execute(sql).fetchall()
```

Treat validation exceptions or missing results as rejection too. Keep the database
catalog and application configuration trusted between validation and execution.

## Functions and results

| Function | Returns | Purpose |
| --- | --- | --- |
| `gatekeeper_validate(sql VARCHAR)` | STRUCT | Validate with effective database defaults. |
| `gatekeeper_validate(sql VARCHAR, options VARCHAR)` | STRUCT | Validate with request overrides. |
| `gatekeeper_configure(options VARCHAR)` | BOOLEAN | Install database defaults once; errors on invalid/repeated configuration. |

The result STRUCT has `allowed BOOLEAN`, `code VARCHAR`, `violations VARCHAR[]`,
`error_type VARCHAR`, and `error_message VARCHAR`.

| Code | Meaning |
| --- | --- |
| `ok` | Validation succeeded. |
| `forbidden` | The query violates policy. |
| `unsupported` | The statement or AST structure is not supported. |
| `parser` | DuckDB could not parse the SQL. |
| `binding` | Resolution failed, for example due to a missing table or column. |
| `invalid_input` | Invalid options, NULL input, or malformed input. |

Only `allowed = true` and `code = 'ok'` indicate success. See [all options, limits,
and error semantics](docs/api.md).

## Trusted catalogs and attached databases

Gatekeeper binds on the calling connection, respecting its temporary tables, search
path, and transaction. Underlying physical tables in views and macros must pass
object policy. Trusted attached-table implementations may read their backing files
without passing caller-facing function restrictions again.

For example, an authorized attached Iceberg table can read its backing
Parquet files, while an explicit caller-written `read_parquet(...)` remains subject
to function policy. Local integration tests exercise an Iceberg REST catalog with
MinIO storage and DuckLake with Parquet-backed local storage. They cover allowed
reads, object denials, trusted views, and write rejection. Other remote catalog
implementations and credential-vending configurations need separate testing.

Gatekeeper is not a sandbox or automatic execution hook. It does not enforce row
policies, runtime deadlines, memory budgets, or network/filesystem isolation.
Function policies authorize names, not function identities. Read the
[security model and known boundaries](docs/security.md) before integration.

## Building from source

Requires Git, Python 3, and a C++17 compiler. The project follows the DuckDB C++
extension-template layout with pinned `duckdb` and `extension-ci-tools` submodules.
Normal builds do not require Go or a Mosaic checkout.

```sh
git clone --recurse-submodules https://github.com/nozzle/duckdb-gatekeeper.git
cd duckdb-gatekeeper
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/build.py --jobs 4
```

For an existing clone, run `git submodule update --init --recursive` first.
The output is `build/release/extension/gatekeeper/gatekeeper.duckdb_extension`.
Add `--shell` to also build the DuckDB CLI with Gatekeeper linked in.

The build generates grammar and native inventory data from pinned source and the
reviewed files in this repository. Changing the DuckDB pin requires a compatibility
review; the generator rejects unsupported revisions.

## Development and testing

```sh
.venv/bin/python -m pytest test -q
.venv/bin/python scripts/audit_inventory.py
.venv/bin/python scripts/benchmark.py --iterations 1000
.venv/bin/clang-format --dry-run --Werror src/*.cpp src/include/*.hpp
.venv/bin/python scripts/test_sanitized.py
```

Tests load the actual extension into DuckDB 1.5.5. They cover function inventories,
CTE scoping, object authorization, configuration/override semantics, DDL/DML
rejection, vectorized calls, concurrency, and adversarial inputs. The sanitizer
runner instruments Gatekeeper and its compiled serializer; see
[sanitizer coverage and limitations](docs/security.md#adversarial-regression-coverage).

Local Apple M3 Max benchmarks through Python measured roughly **0.16–0.28 ms** for
simple through deeply nested queries, including parsing, binding, and conversion
of the STRUCT result. Run the benchmark on your own workloads; these are not
latency guarantees.

## Maintaining the defaults

See [lakehouse integration, native fuzzing, and production review](docs/validation-review.md)
for reproducible local test commands and remaining production boundaries.

Reviewed defaults live in `inventories/core.json` and 29 per-extension files in
`inventories/extensions/`. Compute names are enabled; elevated and unreviewed names
remain excluded. The runtime audit reports changed names, overloads, and versions
without admitting new functions automatically.

Every supported major/minor DuckDB update requires a source and compatibility
review. Follow the [inventory update workflow](inventories/README.md) and
[inventory editing guidance](inventories/AGENTS.md).

## License

[MIT](LICENSE). See [NOTICE](NOTICE) for Mosaic inventory and DuckDB
extension-template provenance and third-party license requirements.
