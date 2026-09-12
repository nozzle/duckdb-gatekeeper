# Integration, fuzzing, and production review

## Clean-checkout builds

The initial GitHub Actions run revealed a shallow-submodule metadata failure:
DuckDB fell back to `v0.0.1` because release tags were unavailable. CI and local
build scripts now supply `OVERRIDE_GIT_DESCRIBE=v1.5.5`; the generator separately
verifies the exact source revision, so this does not allow arbitrary code to be
labelled compatible. CI builds from a fresh checkout on macOS and Linux and loads
the result in the pinned Python runtime.

The cross-platform inventory audit exposed unstable named-argument ordering in
`duckdb_functions()`: table-function signatures list positional arguments first,
then iterate an unordered map. Snapshots now retain positional order and a
name-to-type mapping for named arguments. The baseline migration verified that
the prior signatures changed only in representation; classifications were not
modified. Tests still detect positional reorder and named-argument type changes.

## Local lakehouses

```sh
.venv/bin/python -m pip install -r test/integration/requirements.txt
.venv/bin/python -c "import duckdb; c=duckdb.connect(); c.execute('INSTALL iceberg; INSTALL ducklake; INSTALL httpfs')"
.venv/bin/python scripts/test_lakehouses.py
```

This downloads signed DuckDB extensions and Docker images during setup, then tests
entirely local catalogs/data. Docker Compose starts an Apache Iceberg REST fixture
and MinIO with digest-pinned images. Ports 18181 and 19000 bind only to localhost;
credentials are disposable test values. No host credentials or cloud account are
used. The runner removes its containers/network/volumes even on test failure.
Ports must be free; don't run simultaneous instances on one host.

DuckLake uses temporary local metadata and data paths with row inlining disabled;
both backends must produce actual Parquet files. Tests create schemas,
logical tables, and Parquet-backed data, validate allowed queries, then execute them
and check actual results. They also deny other catalogs/schemas/tables, unqualified
and nested unauthorized references, explicit caller readers, and writes. Trusted
views over authorized lakehouse tables remain usable.

Local macOS arm64 execution passed all four parametrized Iceberg/DuckLake tests
with DuckDB 1.5.5, iceberg `6561bfca`, ducklake `d8a1881e`, and httpfs `827222f`.
These results cover this local REST implementation and DuckLake metadata backend,
not every cloud catalog or credential-vending configuration.

## Coverage-guided fuzzing

```sh
python scripts/generate.py
docker build -t gatekeeper-fuzz -f test/fuzz/Dockerfile test/fuzz
docker run --rm -v "$PWD:/work" gatekeeper-fuzz --seconds 60
```

Or run `CXX=clang++ python scripts/fuzz_native.py --seconds 60` with a compiler that
includes libFuzzer. Apple's bundled clang lacks the libFuzzer archive on the tested
machine, so local coverage-guided testing used Linux arm64 in Docker.

The harness mutates JSON policies and ASTs, including malformed types, and checks
decision consistency. It instruments the validator and yyjson with ASan/UBSan.
It does not exercise DuckDB's SQL parser/binder or prove policy semantics. Those
paths are covered separately by SQL tests and the instrumented-extension suite.
Corpus files, crash artifacts, and logs are retained under ignored `build/fuzz/`.
An initial 61-second campaign completed 4,120,745 executions without a sanitizer
finding or invariant failure. Longer campaigns and stronger semantic oracles remain
useful. A subsequent 181-second campaign completed 12,185,943 executions with no
reported failure. The harness does not execute mutated SQL or contact services.
Longer campaigns and stronger semantic oracles remain
useful; this is not an independent security audit.

## Production boundary review

- Statement types and caller-facing function/capability checks precede binding.
- Resolved table identities come from binder catalog retrieval callbacks, so
  attached logical tables are checked independently of their storage scan operator.
- Trusted catalog expansions may perform internal reads; the application owns
  that trust boundary. Explicitly admitted readers/dynamic SQL are capabilities,
  not an argument-level sandbox.
- Repeated validation rebinds the query; a decision is not cached across catalog
  changes. Validation and later execution are still separate operations, so an
  intervening catalog change is an application-level race to control.
- Defaults are convenience settings, not mandatory policy. The application must
  prevent callers from supplying weaker overrides or configuring defaults first.
- Exact case-sensitive object matching can conservatively deny valid alternate
  spellings. Omitted catalog entries authorize that schema/table across catalogs;
  narrow with `allowed_catalogs` where necessary.
- Traversal budgets do not bound parser/serializer allocation or binding-time I/O.
  Host-language replacement scans, resource quotas, cancellation, and native
  extension trust need application/process controls.

Signing/distribution, long-running fuzzing, additional catalog implementations,
whole-engine sanitizer coverage, and independent review remain release follow-ups.
