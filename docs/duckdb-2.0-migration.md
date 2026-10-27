# DuckDB 2.0 migration and validation

Reviewed 2026-10-27. DuckDB 2.0.0 is the primary build and Gatekeeper v0.4.4 release target.
DuckDB 1.5.6 remains source-compatible and tested until **2027-03-01**, its
[extended upstream EOL](https://duckdb.org/release_calendar.html). The default repin
does not delete its adapters or tests; [#99](https://github.com/nozzle/duckdb-gatekeeper/issues/99)
tracks their retirement. [#90](https://github.com/nozzle/duckdb-gatekeeper/issues/90)
tracks released-parser verification.

## Distribution and host requirements

- New native builds target **DuckDB 2.0.0**, including Windows MinGW with CRAN R 2.0.0.
  Published GitHub v0.4.3 assets still target 1.5.6. Every artifact requires its matching engine.
- Community publication follows the GitHub release through a separate descriptor update.
  Its 1.5.6 binaries remain v0.4.1 until maintainers explicitly rebuild `repo.variegata`.
- Python integrations and the development environment require **Python 3.11+** for 2.0.
  Relation results no longer provide `fetchone()`; the tests retain relation-path coverage
  using `fetchall()`. See the [Python migration guide](https://duckdb.org/docs/2.0/clients/python/migration.html).
- The new Wasm npm runtime uses the release's source but reports `v2.0.0-dev88614`.
  Its matching source build passes browser tests. Stable-2.0 Wasm distribution stays
  deferred until a release-labeled host exists; `runtime.json` and the load-time guard
  enforce the exact tested identity. See [Wasm setup](../test/wasm/README.md).
- Intel macOS is an explicit opt-in in the 2.0 distribution toolchain. MVP and Wasm threads
  remain excluded; the pinned threads toolchain still omits the engine's `USE_WASM_THREADS` flag.

DuckDB 2.0 creates new database files in a format that 1.5 cannot read. Existing files retain
their storage version when 2.0 writes them; mixed-version deployments must explicitly select
compatible storage for new files. The old arrow lambda syntax is disabled by default. See
the [upstream migration guide](https://duckdb.org/docs/2.0/operations_manual/migration.html).
These engine changes are independent of Gatekeeper's policy-v2 document format.

## Authorization and parser changes

- **Dynamic PIVOT remains supported on 2.0.** The released engine invokes `QueryBegin` only
  for the first statement in its rewritten batch, but `ClientContext::CreatePreparedStatement`
  calls `CanRequestRebind` before planning every stage. Gatekeeper uses the engine's new
  statement ID to run the same text admission and private authorization there before later
  stages bind. Each enum query and the final SELECT get their own policy snapshot and audit
  decision. Native callback counters cover readers and bind-time expressions in later stages,
  including retained prepared handles and submitted execution; SQL, Python and Wasm tests
  cover allowed pivots, refusals and per-stage audit records. The 1.5 query-hook path remains supported.
- Validation rejects incomplete types nested inside parameters, including the new `LIST(ANY)`
  sorting placeholders. Concrete typed list parameters remain supported.
- The embedded engine JSON serializer has Gatekeeper-private symbols. This avoids duplicate
  definitions when the 2.0 distribution toolchain links prebuilt/LTO JSON archives alongside it.
- Both default PEG and the optional `legacy_parser` are exercised. The legacy grammar has
  no CONNECT or CREATE SECURE VIEW syntax and cannot name more than three components.
  Tests create trusted secure views/nested schemas with PEG, restore the requested parser,
  and check authorization under that parser. Unsupported written syntax remains a parser error.
  Alternative-parser fixtures (`legacy_parser` on 2.0, `autocomplete` on 1.5) are pinned by
  source revision, archive/binary SHA256 and footer identity in `test/compatibility/parser-pins.json`.
- Released PEG checks `max_expression_depth` during parsing. Worker-stack regressions cover
  nested calls/subqueries at depths 75, 100, 400 and 1000, with 300 submissions per case.
  The optional legacy parser crashes at 1,000 nested calls on macOS; that precise case is
  excluded and reported as [duckdb-legacy-parser#9](https://github.com/duckdb/duckdb-legacy-parser/issues/9),
  with an engine-only reproduction and passing PEG/lower-depth controls. All other cases run.
  The 1.5 PEG crash exclusions remain specific to that engine. Default PEG is the recommended
  2.0 parser for untrusted text.
- Duplicate named arguments now receive DuckDB's bind diagnostic before Gatekeeper's callback.
  Prepared-plan reauthorization and unread-SELECT activation rules remain regression-tested;
  hosts should activate using standalone `CALL gatekeeper_enforce()`.
  R's `dbExecute` prepares and executes separately, so a log-only denial has two records on
  2.0. Its smoke check requires exactly two distinct query IDs; direct-query clients require one.
- `setseed()` again produces reproducible cross-statement draws on released 2.0, so its
  validation-side-effect regression runs on both engines. The QueryBegin transaction-cleanup
  issue remains [duckdb#25876](https://github.com/duckdb/duckdb/issues/25876); its fix
  [duckdb#26446](https://github.com/duckdb/duckdb/pull/26446) is still open.
- PRAGMA argument evaluation remains pre-hook. Its regressions now use the existing
  `table_info` pragma: 2.0 rejects a nonexistent pragma before evaluating its arguments,
  which otherwise gives a misleading passing audit-forgery test.

## Reproducible pins and dependency review

| Component | Pin |
| --- | --- |
| DuckDB source / Python host | `d54cbbe3df17e8e5ce68312f483b4155836112aa` / `2.0.0` |
| Primary extension-ci-tools | `b8d325c37e82160886579880707493bd358c0e62` |
| Retained 1.5 source / host | `069cc9f9b5be802405797faecc284961b07c70ef` / `1.5.6` |
| Retained 1.5 extension-ci-tools | `3fd6109fc01555673b7c7123eba8d0d143fe8ce4` |
| Wasm runtime / toolchain | `1.33.1-dev110.0` / Emscripten `6.0.9` |
| R host | R `4.6.1`, CRAN snapshot `2026-10-26`, DuckDB `2.0.0` |

The full source/label identity of the Wasm host is in `test/wasm/runtime.json`; its Emscripten
image is digest-pinned in `scripts/build_wasm.py`. Quack/httpfs source and compressed artifact
pins are recorded in [the Quack guide](quack.md) and `scripts/test_quack.py` for both engines.

This pass updates CMake to 4.4.4, clang-format to 23.1.3, boto3/botocore to 1.43.118,
Playwright to 1.64.1, and compatible transitive Python packages (including iniconfig 2.3.1,
pluggy 1.7.0, rpds-py 2026.9.1, s3transfer 0.19.3 and urllib3 2.8.0). The three universal
hash locks are regenerated for Python 3.11+, and the retained engine has its own one-package lock.
Ninja 1.13.2, pytest 9.1.1, jsonschema 4.26.0 and esbuild 0.28.2 remain current stable releases.

Actions setup-python/setup-node move to 7.1.0, upload-artifact to 7.0.2 and download-artifact
to 8.0.2, all by full SHA. Checkout 7.0.1, ccache-action 1.2.24 and the R setup pin remain
current on their supported lines. CI keeps Python 3.13 for the shared 1.5/2.0 wheel matrix
and Node 24 LTS for browser tooling. Reusable-workflow internals remain controlled by the
coordinated extension-ci-tools SHA.

Ubuntu 26.04 LTS and Alpine 3.24 image digests are refreshed; the disposable storage fixture
moves to RustFS 1.0.4. The Iceberg REST fixture digest is still current. All image references
remain digest-pinned. The stable Wasm-host deferral above is the remaining distribution blocker.

## Inventory report

The 2.0 Python runtime reports 225 added names, 2 removed names and 132 changed signature
groups against the historical 1.5.5 baseline. There are 223 unclassified runtime names.
The removed names are `icu_collate_yue` and `icu_collate_yue_cn`.
All **919** explicit qualified defaults are preserved. Runtime drift is a maintenance report;
it does not grant discovered names or rewrite historical source evidence and baselines.

## Validation

Completed locally on macOS ARM64:

- Released 2.0 native build and SQL contract: **1,240 assertions in 28 files**.
- Prepared-handle, qualified-function and remote-catalog probes, both statically linked and
  explicitly loading the artifact into the co-built engine; the load-time engine guard probe passes.
- Released 2.0 Quack: **17 passed**, no skips.
- Retained 1.5 Quack: **16 passed**, one unavailable 2.0 routing-feature case skipped.
- Iceberg/RustFS and DuckLake: **10 passed** (the separate Quack cases are not selected by this runner).
- Matched Wasm EH/base Chromium runtime: **51 checks passed**, including exact engine label/source.
- Inventory audit and PEG worker-depth checks.
- Official 2.0 macOS CLI loadable smoke and independent engine-stamp check.
- Rebuilt Ubuntu fuzz image: native AST fuzz smoke **3,855,202 executions**; linked SQL/option
  fuzz smoke with Homebrew LLVM **2,177 executions**, both without findings. Apple Clang's
  installation lacks libFuzzer; the linked smoke uses the installed Homebrew LLVM toolchain.

Full Python parser/engine suites, final formatting, sanitizer/fuzz runs and the changed
Actions/distribution jobs are release gates; their final results are recorded in the migration PR.
