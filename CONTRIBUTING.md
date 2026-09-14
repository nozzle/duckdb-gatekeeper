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
`scripts/build_wasm.py` share these `--duckdb-source`/`--duckdb-version` options
(`test_sanitized.py` runs its suite inside the pinned `duckdb` Python package, so it only
accepts an engine identifying as that release). A checkout at exactly the pinned engine
revision is stamped with the release pin (`OVERRIDE_GIT_DESCRIBE=v1.5.5`), because a shallow
clone cannot `git describe` the engine and DuckDB would otherwise stamp a dummy `v0.0.1`
that no real engine loads. Every other checkout, including another revision inside `duckdb/`,
uses its own Git metadata unless `--duckdb-version vX.Y.Z` overrides it; the `Makefile`
applies the same revision-gated rule, so a community rebuild for a newer engine is never
labeled as the pinned release. Compatibility requires the build and regression
tests to pass; it does not require reclassifying existing function names. See
[build-pin maintenance](inventories/README.md#repinning-the-engine). The
`Engine rebuild compatibility` workflow rebuilds against a post-release engine snapshot
through both the direct CMake path and the community `make release` path, checks the
stamped engine identity against the candidate checkout's own `git describe`, and loads
the resulting artifact into that engine's shell.

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
.venv/bin/python scripts/audit_inventory.py
.venv/bin/clang-format --dry-run --Werror src/*.cpp src/include/*.hpp test/fuzz/*.cpp
.venv/bin/python scripts/test_sanitized.py      # ASan/UBSan rebuild and pytest
.venv/bin/python scripts/benchmark.py --iterations 1000
```

The suite has two layers with different reach:

- `test/sql/*.test` is the **portable contract**: sqllogictests that the community build
  (`make test_release`) and the engine-rebuild workflow run on every platform, including
  Windows, musl, and engines other than the pinned one. They cover statement rejection,
  the never-bind list, strict function allowlists, table allow/block/wildcard rules,
  replacement scans, trusted expansions, and nested bound implementations. Add a case
  here whenever a behavior must hold everywhere the extension is distributed.
- `test/*.py` is the **deep suite**: adversarial, tooling, packaging, and documentation
  tests that run against the loadable artifact on Linux and macOS. Set
  `GATEKEEPER_EXTENSION=/path/to/gatekeeper.duckdb_extension` to point it at another
  artifact; the distribution workflow does this with the downloaded platform artifacts.

`scripts/smoke_loadable.py <artifact>` loads a distributed artifact into the pinned DuckDB
Python package and exercises the checks that cross the host/loadable ABI boundary
(bind-data inspection for lambdas and dispatched aggregates, replacement-scan callbacks,
the policy setting). `scripts/check_engine_stamp.py` verifies the engine identity DuckDB
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

Disposable localhost Iceberg/MinIO and DuckLake fixtures. Ports 18181 and 19000 must be
free; the runner removes its containers and data afterward.

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
DuckDB and DuckDB-Wasm are excluded and bumped manually together with the submodule,
release metadata, fuzz image, and Wasm runtime pin; historical inventory baselines are
maintained independently. See
[AGENTS.md](AGENTS.md).

## Function inventories

Core and 29 extension inventories classify names as compute, elevated, or unreviewed.
Only compute names become defaults. Runtime audits report changes without admitting
functions automatically or blocking engine upgrades. Review names when adding or
changing defaults; existing implementations are trusted across upgrades. Historical
source notes and baselines remain independent of build-engine versions. Follow the
[inventory workflow](inventories/README.md) and [inventories/AGENTS.md](inventories/AGENTS.md).

## Implementation structure

- `src/gatekeeper_extension.cpp`: SQL API, policy snapshot, parse/preflight/bind orchestration,
  replacement interception, and structured error/result handling.
- `src/authorization.cpp`: catalog authorization and iterative bound-plan implementation
  checks, including executable lambda/list-aggregate bind data.
- `src/validator.cpp`: fail-closed serialized AST grammar walk and syntax policy.
- `src/options.cpp`: shared option specifications, typed decoding, and canonical global settings.
- `versions.cmake`: canonical extension/engine metadata; generation emits `version.hpp`.

DuckDB's ordinary expression iterator does not enumerate executable function bind data.
When reviewing a new engine, inspect those representations explicitly; a successful
catalog callback alone does not establish complete function coverage.

## Pull requests

Run the full pytest suite, the inventory audit, and `clang-format` before opening a PR.
Changes to policy semantics should include regression tests and, where they affect the
configuration or validation paths, a fuzz smoke run. Summarize validation results in the
PR description.

## Releases and community publication

Follow the [release checklist](docs/releasing.md). The distribution workflow builds and
tests version tags, then publishes unsigned platform archives and checksums to a GitHub
Release. Community publication is a separate, manually submitted descriptor update.
