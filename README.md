# Gatekeeper for DuckDB

[API reference](docs/api.md) · [Security model](docs/security.md) · [Function inventories](inventories/README.md)

A DuckDB extension for checking SQL against a configurable policy before running it.
Gatekeeper checks caller-authored syntax/functions, then binds references to authorize
actual tables and views. Results are native STRUCTs with structured diagnostics.

- **864 reviewed function defaults**, with exact-name additions and blocks.
- **Resolved catalog/schema/table/view authorization**, including unqualified names.
- **Read-only statements**, type/collation permissions, capability restrictions, and AST limits.
- **Replaceable, lockable global policy** and narrowing-only typed request overrides.

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

**Browser/Wasm:** the EH bundle is supported with a pinned DuckDB-Wasm runtime
embedding DuckDB 1.5.5. See [Wasm installation and browser tests](test/wasm/README.md)
for building/loading the extension and the excluded MVP/threads targets.

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
    allowed_tables := [{catalog: 'memory', schema: 'reporting', 'table': 'orders'}]
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

`allowed_functions` adds names within a policy layer; `blocked_functions` wins.
Requests must also satisfy the global policy: new capabilities must first be granted
by trusted configuration, and request options can only narrow that ceiling.
Functions match exact ASCII-case-folded leaf names. `'*'` names multiplication—it is
not a wildcard. Object policies intersect and use resolved identities. Empty object
lists deny objects; omitted options inherit effective defaults.

Most callers need no function overrides. `{}` JSON and `resolve_objects` are not
accepted. Missing tables or invalid columns fail binding instead of passing syntax-only
validation. All [options and limits](docs/api.md) apply to the same complete path.

## Database-wide policy

```sql
CALL gatekeeper_configure(
    allowed_schemas := ['reporting'],
    blocked_functions := ['md5']
);
-- true
```

```sql
SELECT gatekeeper_validate('SELECT md5(''hello'')', blocked_functions := []).allowed AS allowed;
-- false
```

Configuration is shared by all connections in one instance, not persisted, and not
undone by rollback. Each `CALL` atomically replaces the whole policy, starting from
built-in defaults for omitted options. Inspect it with
`SELECT current_setting('gatekeeper_policy')`; reset with `RESET gatekeeper_policy`.
After trusted setup, `SET lock_configuration=true` prevents changes unless the host
explicitly included `gatekeeper_policy` in `allowed_configs`.

Request lists replace inherited lists in the request layer, but **both the global and
request layers must authorize the query**. Limits use the stricter value. Use the
parameterized `CALL` authoring API; direct STRUCT `SET` has DuckDB casting limitations.
See [configuration and migration](docs/api.md#global-policy-and-configuration).

## Python

```python
import duckdb

db = duckdb.connect(config={"allow_unsigned_extensions": "true"})
db.execute("LOAD '/absolute/path/to/gatekeeper.duckdb_extension'")
db.execute("CREATE SCHEMA reporting")
db.execute("CREATE TABLE reporting.orders AS SELECT 20.0 AS amount")
db.execute("CALL gatekeeper_configure(allowed_schemas := ?)", [["reporting"]])
db.execute("SET lock_configuration=true")
sql = "SELECT sum(amount) FROM reporting.orders"
decision = db.execute(
    "SELECT gatekeeper_validate(?, allowed_schemas := ?)",
    [sql, ["reporting"]],
).fetchone()[0]
if not decision["allowed"] or decision["code"] != "ok":
    raise ValueError(decision)
expected_objects = [{"catalog": "memory", "schema": "reporting", "table": "orders", "type": "table"}]
if decision["objects"] != expected_objects:
    raise ValueError("Unexpected binding dependencies", decision["objects"])
print("Validated dependencies:", decision["objects"], decision["functions"])
rows = db.execute(sql).fetchall()
```

Reject validation exceptions/missing results too. Keep the catalog trusted between
validation and execution. Each violation has a stable `rule`, human `message`,
object/function identifiers, and an optional parser byte `position`. See the
[result contract](docs/api.md#result) rather than parsing English messages.
Dependency lists are sorted, deduplicated binding evidence, empty on failure; they
do not prove unchanged definitions or close TOCTOU. Parameterized SQL is supported
when binding can finish without values (e.g. typed predicates and LIMIT parameters).
Computed expressions in reviewed bind-time positions are rejected before binding;
see the [connection profiles](docs/security.md#validating-connection-profiles).

## Trusted objects and readers

Views **and** their underlying tables must pass object policy, including views
backed only by reader functions. Authorized attached Iceberg/DuckLake tables may
use their internal Parquet readers without exposing those functions to callers.
Explicit admitted readers are capabilities whose resource access the application
controls. Host-language and implicit replacement scans are rejected; use explicit
admitted readers or trusted catalog objects.
Explicit function blocks also apply inside trusted expansions. A non-overridable
[never-bind list](docs/security.md#never-bind-functions) excludes dynamic SQL,
metadata bypasses and sequence/storage operations. User-defined/extension cast
types require `allowed_types`; nondefault collations require explicit permission.
Provision extensions before disabling autoload/autoinstall on validation connections.

Gatekeeper is not a sandbox: no row authorization, execution deadlines, memory
budgets, or filesystem/network isolation. Trusted macros and extensions can perform
binding-time work. Read [security boundaries](docs/security.md) before integrating.

## Building from source

Requires Git, Python 3.10+, and a C++17 compiler. Python's standard library is
sufficient to generate and build Gatekeeper: inventory validation at build time uses the
bundled `scripts/schema_check.py`, so community distribution images need no extra
packages. Development tests additionally use the pinned `jsonschema` (via
`requirements-dev.txt`) as an oracle to verify that validator. The standard C++ template
layout uses pinned DuckDB and extension-ci-tools submodules.

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
reviewed inventories into the build tree; unsupported engine revisions are rejected at
configure time, and the extension also refuses to load into any other DuckDB release.

`requirements-dev.txt`, `requirements-inventory.txt`, and `test/integration/requirements.txt`
are hash-pinned, platform-universal lock files generated from the matching `.in` files. Edit
the `.in` file, then regenerate with
`uv pip compile --universal --generate-hashes --python-version 3.10 -o <name>.txt <name>.in`
(from [uv](https://docs.astral.sh/uv/)); the universal resolution keeps Windows-only and
Python-version-conditional dependencies such as `colorama`. Plain `pip install -r` verifies
the hashes automatically.

The community-extension build path (`make release` with the pinned `extension-ci-tools`
Makefile, then `make test_release` for the sqllogictests in `test/sql`) also works and is
exercised on CI together with the multi-platform distribution pipeline.

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
exercises SQL parsing, typed options, and catalog binding. The image is built from the
repository root so it can install the hashed lock file; sources are bind-mounted at run
time. Corpus, logs, and crash artifacts stay in ignored `build/` directories. The linked
fuzzer also runs weekly on CI. See the sanitizer scope in
[security.md](docs/security.md#adversarial-regression-coverage).

## Maintaining defaults

Core and 29 extension inventories contain compute, elevated, and unreviewed names.
Only compute names become defaults. Runtime audits detect changes without admitting
functions automatically. Every supported major/minor update requires review; follow
the [inventory workflow](inventories/README.md) and [agent guidance](inventories/AGENTS.md).

## License

[MIT](LICENSE). See [NOTICE](NOTICE) for provenance and third-party requirements.
