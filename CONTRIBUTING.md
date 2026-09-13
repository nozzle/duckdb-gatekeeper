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
from the exact pinned DuckDB revision and compiles the reviewed inventories into the
build tree. It needs only the Python standard library, so distribution images require no
extra packages. Any other engine revision is rejected at configure time, and the built
extension refuses to load into any other DuckDB release. Repinning is a coordinated
change; follow [inventories/README.md](inventories/README.md#repinning-the-engine) and
[AGENTS.md](AGENTS.md).

The community-extension build path also works and runs on CI:

```sh
make release          # pinned extension-ci-tools Makefile
make test_release     # sqllogictests in test/sql
```

## Testing

```sh
.venv/bin/python -m pytest test -q
.venv/bin/python scripts/audit_inventory.py
.venv/bin/clang-format --dry-run --Werror src/*.cpp src/include/*.hpp test/fuzz/*.cpp
.venv/bin/python scripts/test_sanitized.py      # ASan/UBSan rebuild and pytest
.venv/bin/python scripts/benchmark.py --iterations 1000
```

`test/test_documentation.py` executes every ```` ```sql ```` block in `README.md` in
order against a fresh database and checks the results, so README examples must stay
runnable and their expected values must match.

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
runs weekly on CI. See the sanitizer scope in
[docs/security.md](docs/security.md#adversarial-regression-coverage).

## Dependencies

`requirements-dev.txt`, `requirements-inventory.txt`, and
`test/integration/requirements.txt` are hash-pinned, platform-universal lock files
generated from the matching `.in` files. Edit the `.in` file, then regenerate with
[uv](https://docs.astral.sh/uv/):

```sh
uv pip compile --universal --generate-hashes --python-version 3.10 -o <name>.txt <name>.in
```

Dependabot handles GitHub Actions, Docker, and pip updates monthly. DuckDB is excluded
and bumped manually together with the submodule, version checks, fuzz image, and
inventory baseline; see [AGENTS.md](AGENTS.md).

## Function inventories

Core and 29 extension inventories classify names as compute, elevated, or unreviewed.
Only compute names become defaults. Runtime audits detect changes without admitting
functions automatically, and unreviewed names are never promoted by tooling. Every
supported DuckDB update requires review: follow the
[inventory workflow](inventories/README.md) and [inventories/AGENTS.md](inventories/AGENTS.md).

## Pull requests

Run the full pytest suite, the inventory audit, and `clang-format` before opening a PR.
Changes to policy semantics should include regression tests and, where they affect the
configuration or validation paths, a fuzz smoke run. Summarize validation results in the
PR description.
