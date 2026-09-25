# Contributing

## Building

Requires Git, Python 3.10+, and a C++17 compiler. The pinned `duckdb` and
`extension-ci-tools` submodules provide the standard extension-template layout.

```sh
git clone --recurse-submodules https://github.com/nozzle/duckdb-gatekeeper.git
cd duckdb-gatekeeper
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/build.py --jobs 4
```

For existing clones run `git submodule update --init --recursive`. The artifact is
`build/release/extension/gatekeeper/gatekeeper.duckdb_extension`; add `--shell` to also
build the CLI.

Generation (`scripts/generate.py`, run at CMake configure time) derives the SQL grammar
from the DuckDB source actually being compiled and compiles the function name list into
the build tree. It needs only the Python standard library. Our submodule and release
tooling remain pinned for reproducibility, but community builds can use another engine.
DuckDB's normal extension checks require a matching binary, and Gatekeeper re-checks
the build engine at load time (see [Compatibility and review](docs/security.md#compatibility-and-review));
there is no fixed engine-version restriction. To test another checkout without changing
the submodule:

```sh
.venv/bin/python scripts/build.py --duckdb-source /path/to/duckdb --build-dir build/candidate --shell
```

`scripts/build.py`, `scripts/test_sanitized.py`, `scripts/fuzz_sql.py`, and
`scripts/build_wasm.py` share these `--duckdb-source`/`--duckdb-version` options and the
CMake invocation behind them (`scripts/engine.py`); what differs between them (build type,
sanitizer and fuzzer options, targets, the Emscripten container) stays in each script
(`test_sanitized.py` runs its suite inside the pinned `duckdb` Python package, so it only
accepts an engine identifying as that release). `--duckdb-version` tells the engine build how
to label itself; the identity CMake then computes is what `scripts/generate.py` bakes into the
load-time guard, through its own `--engine-version-label`/`--engine-source-id`. A checkout at exactly the pinned engine
revision is stamped with the release pin (`OVERRIDE_GIT_DESCRIBE=v1.5.5`), because a shallow
clone cannot `git describe` the engine and DuckDB would otherwise stamp a dummy `v0.0.1`
that no real engine loads. Every other checkout, including another revision inside `duckdb/`,
uses its own Git metadata unless `--duckdb-version vX.Y.Z` overrides it; the `Makefile`
applies the same revision-gated rule, so a community rebuild for a newer engine is never
labeled as the pinned release. Compatibility requires the build and regression
tests to pass; it does not require reclassifying existing function names. See
[build-pin maintenance](inventories/README.md#repinning-the-engine). The
`Engine rebuild compatibility` workflow rebuilds against two pinned engine snapshots, one
past the pinned release on its line and one on the next major's branch (`v2.0-cyanoptera`,
the engine the community repository builds a descriptor's `ref_next` against), through both
the direct CMake path and the community `make release` path; it checks the stamped engine
identity against what the candidate checkout labels itself, runs `test/sql`, and runs
`scripts/check_engine_guard.py`, which loads the resulting artifact into that engine's
`unittest` runner and proves the load-time guard refuses a copy stamped for another engine.
(A shell with Gatekeeper linked in cannot do that: `LOAD` of a file by that name answers
"already loaded" without opening it.)

The community-extension build path also works and runs on CI:

```sh
make release          # pinned extension-ci-tools Makefile
make test_release     # sqllogictests in test/sql
make release OVERRIDE_GIT_DESCRIBE=v1.5.6   # label a shallow clone of another engine explicitly
OVERRIDE_GIT_DESCRIBE= make release         # force the checkout's own tags, even for the pinned revision
```

### Loading unsigned builds

Source builds, CI artifacts, and GitHub Release binaries are unsigned. Use the DuckDB
engine matching the binary (1.5.5 for our release artifacts) and explicitly enable
unsigned loading for these development artifacts:

```sh
duckdb -unsigned
```

```sql
LOAD '/absolute/path/to/duckdb-gatekeeper/build/release/extension/gatekeeper/gatekeeper.duckdb_extension';
```

With Python:

```python
import duckdb

connection = duckdb.connect(config={"allow_unsigned_extensions": True})
connection.execute("LOAD '/absolute/path/to/gatekeeper.duckdb_extension'")
```

For a GitHub Release, select the archive for your DuckDB platform and engine version,
verify it against `SHA256SUMS`, and extract it before loading. The binary retains its
canonical filename inside the archive. A checksum detects corruption; it does not
make an unsigned extension a DuckDB-signed community build. See the
[Wasm instructions](test/wasm/README.md) for EH loading and its pinned runtime.

## Testing

```sh
.venv/bin/python -m pytest test -q
GATEKEEPER_PARSER=peg .venv/bin/python -m pytest test -q  # the same suite under DuckDB's PEG parser
.venv/bin/python scripts/audit_inventory.py
.venv/bin/clang-format --dry-run --Werror src/*.cpp src/include/*.hpp test/fuzz/*.cpp test/native/*.cpp
.venv/bin/python scripts/test_sanitized.py      # ASan/UBSan rebuild and pytest
.venv/bin/python scripts/benchmark.py --markdown  # the README's Benchmarks table; about a minute
```

The suite has two layers with different reach:

- `test/sql/*.test` is the **portable contract**: sqllogictests that the community build
  (`make test_release`) and the engine-rebuild workflow run on every platform the reusable
  pipeline tests, including Windows, musl, and engines other than the pinned one (it skips
  `linux_arm64` and the cross-compiled `osx_amd64`; the distribution workflow's loadable jobs
  cover those with the Python suite). They cover statement rejection,
  the never-bind list, strict function allowlists, table allow/block/wildcard rules,
  replacement scans, trusted expansions, nested bound implementations, enforced
  connections, log-only mode, the audit log, and the refusals DuckDB 2.0 introduced that hold on both
  engines (DML inside a CTE), plus nested-schema coverage on 2.0. Add a case here whenever a behavior must hold
  everywhere the extension is distributed.
- `test/*.py` is the **deep suite**: adversarial, tooling, packaging, and documentation
  tests that run against the loadable artifact on Linux and macOS here, and on every target
  the pinned Python package has a wheel for in the distribution workflow (Linux, macOS, and
  Windows, both architectures each). Set
  `GATEKEEPER_EXTENSION=/path/to/gatekeeper.duckdb_extension` to point it at another
  artifact; the distribution workflow does this with the downloaded platform artifacts.
  `GATEKEEPER_PARSER=peg` runs the same suite with every connection `support.artifact.connect`
  opens opted into the `autocomplete` extension's PEG parser override
  (`CALL enable_peg_parser()`, DuckDB 1.5's experimental parser and the only parser from 2.0; it
  needs `INSTALL autocomplete` once). A test that must open a raw connection because the
  artifact's load path is what it tests applies the leg with `select_parser()` once the
  artifact is loaded. The tests that compile against the engine's headers or generate the
  grammar from its schema (`test_validator_structure.py`, `test_engine_errors.py`,
  `test_versions.py`'s stamp check) use the submodule unless `GATEKEEPER_ENGINE_SOURCE` names
  the checkout the artifact was built from.
  Gatekeeper parses with the connection's parser options, so its decisions must agree with the
  engine under either parser; the build-and-test workflow runs both legs. The parsers differ in
  a few diagnostics (which AST nodes carry a query location, whether `max_expression_depth` is
  the parser's or the binder's check, the arity a keyword-named call such as `position` must
  have to reach the binder), so a test that pins one of those names both expectations with
  `by_parser(postgres=..., peg=...)` from `support.artifact` rather than skipping a leg. A
  policy decision (`allowed`, a `forbidden`/`unsupported` code, a violation's `rule`) must
  never need `by_parser`; the engine-error codes `parser` and `binding` may, since they name
  the stage that refused the text. The one thing a leg may skip is a case that crashes the
  engine under that parser (`test_robustness.py`'s deep nesting under PEG, duckdb#24618, see
  [Compatibility and review](docs/security.md#compatibility-and-review)); the skip names the
  engine defect, and removing it is part of the repin that carries the fix
  ([#90](https://github.com/nozzle/duckdb-gatekeeper/issues/90) is that repin's checklist).
  On DuckDB 2.0 the same two cases run: its parser is the heap-based matcher.
- `test/native/*.cpp` are **client-API probes** for behavior neither layer can express: a
  prepared statement handle held across a policy change (`prepared_handle_probe.cpp`; the
  Python package's `executemany` materializes its parameter sets before the first execution, so
  it cannot hold one), and a counted native remote catalog (`remote_catalog_probe.cpp`) that
  proves local CONNECT refusals precede remote dispatch and exercises the documented
  already-connected/native-state limitations on 2.0 (local trusted-control-plane cases on both).
  They link against the engine with Gatekeeper built in, under
  `-DGATEKEEPER_NATIVE_PROBES=ON`, and the engine-rebuild workflow builds and runs them against
  each candidate engine. The parameter-fallback leg on 2.0 also retains handles across session-variable
  changes and counts table-function binds to prove collision refusals precede bind-time work (see
  [the fallback decision](docs/parameter-fallback.md)). Add a probe here when a guarantee is made to a
  client API rather than to SQL text.

### Running the suite on DuckDB 2.0

The same source builds against `v2.0-cyanoptera` (see
[Compatibility and review](docs/security.md#compatibility-and-review) for what the engine
does differently there). The deep suite runs inside a `duckdb` Python package, and the load-time
guard requires that package to be the exact engine the artifact was built from: for a
prerelease that means DuckDB's nightly wheels (`pip install --pre --extra-index-url
https://artifacts.duckdb.org/duckdb-python/nightly/simple duckdb==2.0.0.devN`), whose
`PRAGMA version` names the engine commit and label to build against:

```sh
git -C build/candidate-source checkout <commit from PRAGMA version>
cmake -G Ninja -S build/candidate-source -B build/v2 -DCMAKE_BUILD_TYPE=Release \
  -DOVERRIDE_GIT_DESCRIBE=<library_version from PRAGMA version> \
  -DDUCKDB_EXTENSION_CONFIGS=$PWD/extension_config.cmake -DUNITTEST_ROOT_DIRECTORY=$PWD \
  -DENABLE_UNITTEST_CPP_TESTS=OFF -DBUILD_SHELL=ON -DGATEKEEPER_NATIVE_PROBES=ON
cmake --build build/v2 --target unittest shell gatekeeper_loadable_extension gatekeeper_prepared_probe gatekeeper_remote_probe
GATEKEEPER_TEST_NESTED_SCHEMAS=1 build/v2/test/unittest 'test/sql/*'
build/v2/extension/gatekeeper/gatekeeper_prepared_probe
build/v2/extension/gatekeeper/gatekeeper_remote_probe
python scripts/check_engine_guard.py --extension build/v2/extension/gatekeeper/gatekeeper.duckdb_extension --unittest build/v2/test/unittest
GATEKEEPER_EXTENSION=$PWD/build/v2/extension/gatekeeper/gatekeeper.duckdb_extension \
  GATEKEEPER_ENGINE_SOURCE=$PWD/build/candidate-source \
  <venv with that wheel>/bin/python -m pytest test -q --ignore test/test_inventory_tooling.py
```

On 2.0 the suite has one parser leg (`peg`); `test_inventory_tooling.py` tests the pin tooling
against the submodule and stays on the pinned engine. Engine behavior a test pins that 2.0
changed is named on both sides with `by_engine(v1=..., v2=...)` from `support.artifact`, under
the same rule as `by_parser`: never a policy decision. The 1.5 side of every such site, and of
the `#if GATEKEEPER_DUCKDB_MAJOR` branches in `src/`, is removed by the repin that moves the
engine to 2.0; [#99](https://github.com/nozzle/duckdb-gatekeeper/issues/99) is that repin's
checklist.

`test/sql/nested_schemas.test` requires `GATEKEEPER_TEST_NESTED_SCHEMAS=1` because 1.5 cannot
create nested schemas. Both 2.0 engine-rebuild CI jobs set it. `schema_paths.test` exercises
the explicit path API on every engine; `test_schema_paths.py` adds deeper 2.0 coverage.
`test/sql/connect.test` uses the same 2.0 feature marker for CONNECT syntax; the native
remote-catalog probe additionally verifies callback ordering with an actual routing target.

The two layers overlap on purpose and the overlap is not a cleanup target: a behavior that
appears in both is checked on the static build on every platform *and* on the loadable
artifact through the Python API. Remove a duplicate only after mapping which execution path
each side covers (static vs loadable, `unittest` vs the Python package, the platforms each
runs on) and confirming the survivor covers both.

`pytest.ini` puts `scripts/` and `test/` on the import path. Fixtures (`db`, `catalog`,
`agent`) live in `test/conftest.py`; functions and constants live in `test/support/` and
are imported explicitly (`from support.typed_helpers import validate`), never from a test
module or from `conftest`. `support.corpus` holds the catalog and statements the three
parity legs share (`test_enforcement`, `test_audit`, `test_log_only`); each leg keeps its
own assertions. `support.headers` is the one reader of the name lists in
`src/include/function_policy.hpp`; `test_documentation.py` checks the never-bind list in
`docs/security.md` against it, and `test_resolved_functions.py` keeps a written-out sample
of names that must stay denied whatever the header says.

The scripts are grouped by responsibility: `scripts/engine.py` (engine selection and the
shared CMake invocation), `scripts/artifact.py` (the default loadable path and the
connect-plus-`LOAD` idiom; it imports `duckdb`, which nothing on the generation path may do),
`scripts/sanitize.py` (sanitizer options and the libFuzzer run), `scripts/descriptor.py`
(the community descriptor's pins and `hello_world` block), and `scripts/versions.py` (the
canonical metadata; run as a script it prints the job outputs the workflows read). The
modules CMake runs at configure time (`versions`, `inventory`, `schema_check`, `generate`)
need only the standard library, which `test_inventory_tooling.py` checks by importing each
with `duckdb` and `pytest` blocked.

`scripts/smoke_loadable.py <artifact>` loads a distributed artifact into the pinned DuckDB
Python package and exercises the checks that cross the host/loadable ABI boundary
(bind-data inspection for lambdas and dispatched aggregates, replacement-scan callbacks,
the policy setting, and an enforced connection with the audit log and log-only mode through
the host's query hooks and log manager). The same checks exist as plain SQL in
`scripts/smoke/loadable.sql` (one connection, every check asserting with `error()` inside SQL)
and `scripts/smoke/enforced.sql` (two connections, one `-- @host`/`-- @agent` directive per
paragraph): the form the hosts without a Python package run, `scripts/smoke_loadable.R` through
the CRAN package for MinGW (both files) and `scripts/smoke_cli.sh` through the engine's musl CLI
(`loadable.sql` as one stdin script; the CLI is one connection, so the script replays the
enforced half by hand as separate processes, and a change to `enforced.sql` has to be mirrored
there).
`smoke_loadable.py` runs those files too, and `test/test_smoke_sql.py` runs them against the
local build, so a change to them is exercised here before it reaches those hosts; keep every
statement of `loadable.sql` runnable as one stdin script (the CLI reads it under `-bail`), and in
`enforced.sql` do not follow a denial directly with a statement the engine preprocesses inside a
transaction (a rewritten `PRAGMA`, a dynamic `PIVOT`, a relation-API statement), which fails on
DuckDB 2.0 until a plain statement has ended the denied one (`test/support/enforcement.py`,
`settle()`); any other statement, refused or not, may follow a denial. `scripts/check_engine_stamp.py` verifies the engine identity DuckDB
and Gatekeeper stamped into an artifact against the engine checkout it was built from,
independently of any shell built alongside it.

`test/test_documentation.py` executes every ```` ```sql ```` block in `README.md` in
order against a fresh database, except the exact community installation block,
and checks the results. It parses all blocks first and rejects installation-block
drift before any examples execute, so edits cannot trigger remote extension loading.
README examples must stay runnable and their expected values
must match.

The pipeline diagram in the README is `docs/pipeline.svg`, exported from the
[Archify](https://github.com/tt-a1i/archify) specification `docs/pipeline.dataflow.json`.
Edit the JSON, re-render, and export the SVG rather than editing the SVG by hand.

### Lakehouse integration

Disposable localhost Iceberg/RustFS and DuckLake fixtures. Ports 18181 and 19000 must be
free; the runner removes its containers and data afterward. The tests cover
`gatekeeper_validate`, enforced connections, and log-only mode against each lake's real
catalog and scan function.

```sh
.venv/bin/python -m pip install -r test/integration/requirements.txt
.venv/bin/python -c "import duckdb; c=duckdb.connect(); c.execute('INSTALL iceberg; INSTALL ducklake; INSTALL httpfs')"
.venv/bin/python scripts/test_lakehouses.py
```

### Fuzzing

Coverage-guided libFuzzer targets, built in Docker with Clang:

```sh
python3 scripts/generate.py
docker build -t gatekeeper-fuzz -f test/fuzz/Dockerfile .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" gatekeeper-fuzz --seconds 60
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" --entrypoint python3 gatekeeper-fuzz scripts/fuzz_sql.py --seconds 60
```

The first target exercises the AST walker and yyjson; the second links DuckDB and
exercises SQL parsing, typed options, catalog binding, and configuration paths. Corpus,
logs, and crash artifacts stay in ignored `build/` directories. The linked fuzzer also
runs on every PR/main push and weekly on CI. Its deterministic startup regressions
cover native policy setters and replacement callbacks. See the sanitizer scope in
[docs/security.md](docs/security.md#adversarial-regression-coverage).

## Dependencies

`requirements-dev.txt`, `requirements-inventory.txt`, and
`test/integration/requirements.txt` are hash-pinned, platform-universal lock files
generated from the matching `.in` files. Edit the `.in` file, then regenerate with
[uv](https://docs.astral.sh/uv/):

```sh
uv pip compile --universal --generate-hashes --python-version 3.10 -o <name>.txt <name>.in
```

Dependabot handles GitHub Actions, Docker, pip, and the `test/wasm` npm lock monthly.
DuckDB and DuckDB-Wasm are excluded: the engine is repinned by hand, following the
procedure in [inventories/README.md](inventories/README.md#repinning-the-engine).

## Function inventories

Core and 29 extension inventories classify names as compute, elevated, or unreviewed.
Only compute names become defaults. Runtime audits report changes without admitting
functions automatically or blocking engine upgrades. Review names when adding or
changing defaults; existing implementations are trusted across upgrades. Historical
source notes and baselines remain independent of build-engine versions. Follow the
[inventory workflow](inventories/README.md) and [inventories/AGENTS.md](inventories/AGENTS.md).

## Implementation structure

- `src/gatekeeper_extension.cpp`: `gatekeeper_validate`, extension load order, and the
  build-engine load guard.
- `src/policy_setting.cpp`: the `gatekeeper_policy` setting (its SET callback and every read of
  it, `GlobalPolicy`) and `CALL gatekeeper_configure()`, the two ways a host writes the ceiling.
- `src/result_value.cpp`: the structured shape of a decision, `ResultType`/`ResultValue`: the
  columns of `gatekeeper_validate` and the body of every audit record.
- `src/check.cpp`: the decision. `CheckText` is the binding boundary (parse, serialize,
  grammar walk; never binds), `Authorize` is the private bind with the catalog-lookup
  callback and replacement-scan interception, `CheckPlan` is the execution boundary
  (read-only operator allowlist and bound-plan authorization), and `Check` composes them
  into `gatekeeper_validate`'s structured result.
- `src/enforcement.cpp`: enforced connections. The per-connection enforced state
  (`ClientContextState`), the `QueryBegin`/`OnExecutePrepared`/post-bind hooks that run the
  same decision inside the engine, the global `gatekeeper_log_only` switch (snapshotted per
  statement; a denial is recorded and not refused), `CALL gatekeeper_enforce()`, and posture
  warnings.
- `src/audit.cpp`: the audit log. `Decide` is the one place a decision becomes observable:
  it writes the `Gatekeeper` log record (the `gatekeeper_validate` columns plus mode,
  boundary, statement, and policy hash) and throws the denial on an enforced connection.
  Every denial site in `enforcement.cpp`, `check.cpp`, and the validate function goes
  through it; setting callbacks record their changes through `LogSettingChange`.
- `src/authorization.cpp`: catalog authorization and iterative bound-plan implementation
  checks, including executable lambda/list-aggregate bind data.
- `src/validator.cpp`: fail-closed serialized AST grammar walk and syntax policy.
- `src/options.cpp`: shared option specifications, JSON-to-typed decoding, typed validation,
  and canonical global settings. `docs/policy-v2.schema.json` describes the JSON input;
  `test/test_json_options.py` checks schema/decoder agreement and typed API equivalence.
- `versions.cmake`: canonical extension/engine metadata; generation emits `version.hpp`.

Two namespaces: `gatekeeper::` is the policy model (`Policy`, `Result`, the result codes and
violation rules, the grammar walk, option decoding), `duckdb::` is everything that touches the
engine (binders, catalog entries, hooks, the SQL surface). The namespace is a naming convention,
not a dependency boundary: `options.cpp` is `gatekeeper::` and uses `duckdb::Value`, and
`engine_errors.hpp` is `gatekeeper::` and names DuckDB's exception types. The one real boundary is
`validator.cpp`, which must compile with nothing but the standard library and yyjson; the native
fuzz build (`scripts/fuzz_native.py`) and `test_validator_structure.py` compile it that way and
are what enforce it.

DuckDB's ordinary expression iterator does not enumerate executable function bind data.
When reviewing a new engine, inspect those representations explicitly; a successful
catalog callback alone does not establish complete function coverage.

## Pull requests

Run the full pytest suite, the inventory audit, and `clang-format` before opening a PR.
Changes to policy semantics should include regression tests and, where they affect the
configuration or validation paths, a fuzz smoke run. Summarize validation results in the
PR description. A change a host integrating the extension would notice (a new function or
setting, a decision that changes, an error class or message the README documents) gets a
line under `## Unreleased` in [CHANGELOG.md](CHANGELOG.md), written for that host rather
than as a commit subject; the release turns that section into the GitHub Release notes.

## Releases and community publication

Follow the [release checklist](docs/releasing.md). The distribution workflow builds and
tests version tags, then publishes unsigned platform archives and checksums to a GitHub
Release. Community publication is a separate, manually submitted descriptor update.
