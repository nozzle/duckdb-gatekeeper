# Gatekeeper for DuckDB

[API reference](docs/api.md) · [Security model](docs/security.md) · [Function inventories](inventories/README.md)

A DuckDB extension for checking SQL against a configurable policy before running it.
Gatekeeper checks caller-authored syntax/functions, then binds references to authorize
actual tables and views. Results are native STRUCTs with structured diagnostics.

- **864 reviewed function defaults**, with exact-name additions and blocks.
- **Resolved catalog/schema/table/view authorization**, including unqualified names.
- **Read-only statements**, capability restrictions, and AST limits.
- **One-time database defaults** and typed per-request overrides.

> Early development. Targets **DuckDB 1.5.5 only**. Not yet published in the community
> repository. No wildcard matching, public syntax-only mode, or automatic execution
> hook. See [the security model](docs/security.md) for limitations.

## Installation

[Build from source](#building-from-source), start `duckdb -unsigned` for the local
development artifact, and load its absolute path:

```sql
LOAD '/absolute/path/to/duckdb-gatekeeper/build/release/extension/gatekeeper/gatekeeper.duckdb_extension';
```

Signed packages and `INSTALL gatekeeper FROM community` are not available yet.

## Quickstart

Provision data through trusted initialization:

```sql
CREATE SCHEMA reporting;
CREATE TABLE reporting.orders (customer_id INTEGER, amount DOUBLE);
INSERT INTO reporting.orders VALUES (1, 20), (1, 30), (2, 15);
```

```sql
SELECT gatekeeper_validate(
    'SELECT customer_id, sum(amount) FROM reporting.orders GROUP BY customer_id',
    allowed_schemas := ['reporting'],
    allowed_tables := [{schema: 'reporting', 'table': 'orders'}]
).allowed AS allowed;
-- true
```

```sql
SELECT gatekeeper_validate('DROP TABLE reporting.orders').code AS code;
-- unsupported
```

```sql
SELECT gatekeeper_validate('SELECT * FROM missing_table').code AS code;
-- binding
```

Your application must require `allowed = true` and `code = 'ok'`, then execute the
same SQL. Validation does not execute the submitted query plan, but **binding may
perform I/O** through trusted catalog implementations and explicitly admitted readers.

## Typed options

There is no JSON options string. Pass native booleans, lists, integers, and table structs:

```sql
SELECT gatekeeper_validate(
    'SELECT md5(''hello'')',
    blocked_functions := ['md5']
).allowed AS allowed;
-- false
```

```sql
SELECT gatekeeper_validate(
    'SELECT 1+2',
    use_default_functions := false,
    allowed_functions := ['+']
).allowed AS allowed;
-- true
```

`allowed_functions` adds names to the reviewed defaults; `blocked_functions` wins.
Functions match exact ASCII-case-folded leaf names. `'*'` names multiplication—it is
not a wildcard. Object policies intersect and use resolved identities. Empty object
lists deny objects; omitted options inherit effective defaults.

Most callers need no function overrides. `{}` JSON and `resolve_objects` are not
accepted. Missing tables or invalid columns fail binding instead of passing syntax-only
validation. All [options and limits](docs/api.md) apply to the same complete path.

## Database-wide defaults

```sql
SELECT gatekeeper_configure(
    allowed_schemas := ['reporting'],
    blocked_functions := ['md5']
);
-- true
```

```sql
SELECT gatekeeper_validate('SELECT md5(''hello'')', blocked_functions := []).allowed AS allowed;
-- true
```

Configuration is shared by all connections in one instance, set once, not persisted,
and not undone by rollback. Request lists replace inherited lists; limits override
individually. Overrides can relax defaults: the application controls their provenance.

## Python

```python
import duckdb

db = duckdb.connect(config={"allow_unsigned_extensions": "true"})
db.execute("LOAD '/absolute/path/to/gatekeeper.duckdb_extension'")
db.execute("CREATE SCHEMA reporting")
db.execute("CREATE TABLE reporting.orders AS SELECT 20.0 AS amount")
sql = "SELECT sum(amount) FROM reporting.orders"
decision = db.execute(
    "SELECT gatekeeper_validate(?, allowed_schemas := ?)",
    [sql, ["reporting"]],
).fetchone()[0]
if not decision["allowed"] or decision["code"] != "ok":
    raise ValueError(decision)
rows = db.execute(sql).fetchall()
```

Reject validation exceptions/missing results too. Keep the catalog trusted between
validation and execution. Each violation has a stable `rule`, human `message`,
object/function identifiers, and an optional parser byte `position`. See the
[result contract](docs/api.md#result) rather than parsing English messages.

## Trusted objects and readers

Views **and** their underlying tables must pass object policy, including views
backed only by reader functions. Authorized attached Iceberg/DuckLake tables may
use their internal Parquet readers without exposing those functions to callers.
Explicit admitted readers are capabilities whose resource access the application
controls. Host-language and implicit replacement scans are rejected; use explicit
admitted readers or trusted catalog objects.

Gatekeeper is not a sandbox: no row authorization, execution deadlines, memory
budgets, or filesystem/network isolation. Trusted macros and extensions can perform
binding-time work. Read [security boundaries](docs/security.md) before integrating.

## Building from source

Requires Git, Python 3.10+, and a C++17 compiler. Install the pinned Python tooling
in `requirements-dev.txt` (including JSON Schema validation). The standard C++ template layout uses
pinned DuckDB and extension-ci-tools submodules.

```sh
git clone --recurse-submodules https://github.com/nozzle/duckdb-gatekeeper.git
cd duckdb-gatekeeper
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/build.py --jobs 4
```

For existing clones, run `git submodule update --init --recursive`. The artifact is
`build/release/extension/gatekeeper/gatekeeper.duckdb_extension`. Add `--shell` for
the CLI. Generation derives the grammar from the exact pinned revision and compiles
reviewed inventories; unsupported engine revisions are rejected.

## Development

```sh
.venv/bin/python -m pytest test -q
.venv/bin/python scripts/audit_inventory.py
.venv/bin/python scripts/benchmark.py --iterations 1000
.venv/bin/clang-format --dry-run --Werror src/*.cpp src/include/*.hpp
.venv/bin/python scripts/test_sanitized.py
```

Tests exercise typed binding, structured errors, policy composition, actual catalog
fixtures, CTE scoping, view dependencies, prepared statements, concurrency, and
adversarial inputs.

For disposable localhost Iceberg/MinIO and local DuckLake integration tests:

```sh
.venv/bin/python -m pip install -r test/integration/requirements.txt
.venv/bin/python -c "import duckdb; c=duckdb.connect(); c.execute('INSTALL iceberg; INSTALL ducklake; INSTALL httpfs')"
.venv/bin/python scripts/test_lakehouses.py
```

Ports 18181 and 19000 must be free. The runner removes its test containers and data
afterward. Setup downloads images/extensions; catalog and storage operations are local.

For coverage-guided native fuzzing with Docker:

```sh
python3 scripts/generate.py
docker build -t gatekeeper-fuzz -f test/fuzz/Dockerfile .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" gatekeeper-fuzz --seconds 60
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" --entrypoint python3 gatekeeper-fuzz scripts/fuzz_sql.py --seconds 60
```

The first target exercises the AST walker/yyjson; the second builds DuckDB and
exercises SQL parsing, typed options, and catalog binding. Corpus, logs, and crash
artifacts stay in ignored `build/` directories. See the sanitizer scope in
[security.md](docs/security.md#adversarial-regression-coverage).

## Maintaining defaults

Core and 29 extension inventories contain compute, elevated, and unreviewed names.
Only compute names become defaults. Runtime audits detect changes without admitting
functions automatically. Every supported major/minor update requires review; follow
the [inventory workflow](inventories/README.md) and [agent guidance](inventories/AGENTS.md).

## License

[MIT](LICENSE). See [NOTICE](NOTICE) for provenance and third-party requirements.
