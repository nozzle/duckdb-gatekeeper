# Reviewed function inventories

Gatekeeper owns its function classifications here:

- `core.json`: built-in groups (operators, aggregates, windows, syntax helpers,
  generators, scalars), default compute names, and excluded names.
- `extensions/*.json`: one file for each reviewed core extension, preserving
  `compute` and `elevated` groups, implementation source links, and review notes/pins.
- `default_identities.json`: explicit default catalog/schema_path/name/type grants,
  grouped by registration evidence and kind, plus reasoned exclusions. Its schema is
  `default_identities.schema.json`; [default provenance](../docs/default-provenance.md)
  records completeness, namespace evidence, intrinsic exceptions and coverage limits.
- `baselines/duckdb-1.5.5.json`: runtime signatures and loaded-extension versions
  captured from the pinned Python DuckDB runtime. This includes Python-specific
  functions; it does not claim that all extensions were loaded or audited live.

Types, casts, and collations are supplied by the database owner and have no
Gatekeeper allowlist or mandatory inventory audit.

## Adjusting defaults

All compiled defaults grant explicit `system.main` identities and concrete kinds, including
reviewed extension functions registered there. Host shadows and `system.pg_catalog` macros
require explicit grants. Runtime discovery remains a maintenance report and never creates
permissions. All 953 historical compute names are accounted for: 913 names contribute 919
identities; 40 pg_catalog-only names are explicitly excluded without reclassification. The audit
reports reviewed names, compiled names, compiled identities, exclusions and qualified drift.
`reporting_discrepancies` records the historical 1.5.5 synthetic window rows labeled
`aggregate`; executable window intrinsics grant only kind `window`. Snapshot labels remain
unchanged and aggregate collisions remain ungranted, even when a discrepancy explains the label.

Move exact normalized names between `compute` and `elevated` after source review.
Only compute names with explicit registration identities are compiled into defaults. Update
the identity map in the same change; missing names, conflicting exclusions, duplicate identities,
unknown kinds, unpinned evidence and non-compute grants fail source-only validation. If a core
function moves, update its descriptive `groups` membership too. `unreviewed` records baseline names without
a completed source review; these remain excluded and must not be promoted
automatically. Unreviewed is not a claim of elevated behavior.

### Classification criteria

A name is `compute` when every overload's output depends only on its arguments plus, at
most, three admitted sources:

- **The clock.** Either `MetaTransaction` start time (`now()`, `current_date`, `ago`) or an
  execution-time `system_clock` read (`uuidv7`, the offsets in `pg_timezone_names`).
- **Non-cryptographic PRNG state.** The connection-local PCG32 engine (`random()`,
  `uuid()`), a query-local engine seeded from it or from OS entropy
  (`st_generatepoints`), and `setseed()`, which reseeds the connection engine. That reseed
  is the one admitted mutation: it is connection-local, its only readers are the RNG
  functions and unseeded `SAMPLE`, and the engine is never a secret.
- **The `TimeZone` and `Calendar` settings.** Every ICU temporal function consumes them
  (`current_localtime`, `date_part` on `TIMESTAMPTZ`, `timezone()`); they are trusted host
  temporal configuration in the same sense that types and collations are trusted, and a
  tenant learns only the host's chosen zone and calendar.

These disclose nothing else about the host, and `current_date` is the most common non-pure
expression in analytic SQL, so excluding them would deny ordinary queries for no gain.

A name is `elevated` when any overload reads catalog, session, configuration, or planner
state (`current_setting`, `current_schema`, `getvariable`, `duckdb_tables`, `stats`),
performs I/O or mutation (readers, `checkpoint`, `nextval`), dispatches by a
caller-supplied name (`query`, `list_aggregate`, `finalize`), consumes resources for their
own sake (`sleep_ms`), takes raw pointers, is an internal/debug/test registration DuckDB
does not harden as a caller surface (`__internal_*`, `test_vector_types`), reveals host
platform details (`pragma_platform`), resolves a caller-supplied name through the catalog
(`make_type`, `st_setcrs`), or evaluates caller expressions at bind time without a
foldability check so that volatile functions run during validation (`switch`). Version
strings fixed by the engine pin are compute.
Registered aliases share their canonical name's classification; the test suite checks this.

`schema.json` rejects unknown keys, malformed source URLs, non-list review notes,
and invalid group shapes. The contract is: **Python's standard library is sufficient to
generate and build Gatekeeper; development tests additionally use `jsonschema` to verify
the validator.** `scripts/schema_check.py` evaluates exactly the JSON Schema keywords the
schema uses and refuses any other keyword anywhere in the schema (including `$defs` and
unselected conditional branches), so a schema edit that needs an unsupported keyword fails
clearly rather than being ignored. The test suite runs generation under `python -S`,
checks that malformed inventories are still rejected there, and cross-checks the validator
against the pinned `jsonschema` package (from `requirements-inventory.txt`) on the real
inventories and on mutated documents. `scripts/inventory.py` then checks metadata shape,
sorting, duplicates, and classification conflicts, including conflicts across extensions.
The build consumes this same loader. Tests exercise every default and every excluded name.

The generator requires Python 3.10+ and the DuckDB source being compiled. CMake passes
that source explicitly, including for external checkouts. `versions.cmake` owns the
extension version and reproducible release build defaults; the historical baseline is
independent of those build defaults. Generated C++ literals are split into
8 KB-or-smaller pieces for MSVC compatibility.

Inventory notes retain provenance, non-obvious classification traps, and coverage limitations.
The optional `audit_inventory.py --check-sources` check compares implementation source
URLs with a checkout of the historical review engine. Normal generation and runtime
reports do not require those sources to match the build engine. UI has an independent source pin because no
engine descriptor exists; MotherDuck records its binary version/hash in `binary_review`
and cannot contribute defaults. Original attribution is retained in `NOTICE`.
Capture and comparison work without submodules. The optional provenance check rejects
ambiguous descriptors with multiple distinct source URLs or revisions.
After repinning the build engine, pass `--check-sources --source-checkout /path/to/review-engine`
to check provenance using a separate historical checkout. Its commit must match the
inventory's recorded core source, not the current release build pin.

## Version update procedure

Function policy matches qualified identities and kinds. Existing DuckDB implementations are trusted across
upgrades; changes behind an existing name are not a backwards-compatibility attack
model. New names remain excluded until explicitly allowed or classified. Maintaining
defaults improves convenience and does not gate engine upgrades.

To investigate coverage on another runtime:

1. Capture the candidate runtime in a separate environment without changing the
   accepted baseline or classifications:

   ```sh
   python scripts/audit_inventory.py --capture build/candidate.json
   ```

2. Compare it with the reviewed baseline:

   ```sh
   python scripts/audit_inventory.py --candidate build/candidate.json
   ```

   Additions, removals, changed overload signatures/macro definitions, engine version,
   and loaded-extension versions are reported without failing. `--strict` optionally
   turns drift into an error for baseline investigations. Unknown names remain excluded;
   they are never added to defaults by enumeration. New captures retain catalog, full nested
   schema paths and kind, including 2.0 windows. Qualified additions/removals/signature changes
   require two qualified snapshots; the historical unqualified baseline is preserved and reported
   as such. Default-name registrations at ungranted identities and defaults not observed in a
   candidate are reported separately. Missing optional extensions and cross-version intrinsic
   kinds are expected reasons for defaults not being observed, not instructions to remove grants.

3. Review names you choose to add or reclassify, including their overloads. Record why
   non-obvious entries are default or elevated and preserve the reviewed source revision.
   Existing names need no repeat implementation review merely because the engine changed.
4. Optionally, capture a separate baseline for an optional extension from a local file
   you already have (`--load-extension /path/to/extension.duckdb_extension`, repeatable),
   whether a signed binary DuckDB installed or an unsigned build of your own; naming the
   file is the trust decision, and the tool never installs, downloads, or auto-loads an
   extension on the user's behalf. Compare it against its baseline with `--baseline`.
   No extension baseline is checked in today: a name an extension adds is unknown until
   reviewed and so already excluded, and a signature baseline cannot see a change behind
   an existing name, so these baselines aid an investigation rather than gate anything.
5. Run generation, the runtime report, full tests, and a build after classification
   changes. Update a historical baseline only intentionally, preserving its provenance.

## Explicit all-extension collection

`scripts/capture_extensions.py` is a separate **opt-in installer/collector** for the
extensions named by `inventories/extensions/*.json`. Its parent needs only the Python
standard library; `--python` chooses the exact DuckDB environment for subprocesses.
Run discovery first, then replay its artifact lock into a new directory:

```sh
python scripts/capture_extensions.py collect --allow-install \
  --python /path/to/duckdb-1.5.5-venv/bin/python \
  --output build/extensions-1.5.5-discovery --discover
python scripts/capture_extensions.py collect --allow-install \
  --python /path/to/duckdb-1.5.5-venv/bin/python \
  --output build/extensions-1.5.5-verified \
  --lock build/extensions-1.5.5-discovery/lock.json
```

Repeat with the candidate Python environment and separate output directories. For
independent capture workers, use `worker --extension iceberg --extension postgres`
with the same required options. `collect --extension NAME` also selects a subset.
Workers each emit their own base and lock; identical `base_sha256` values establish
that their deltas share a base. `--dependency avro` explicitly installs a prerequisite
without loading it independently; repeat for additional prerequisites during discovery.
Omit `--dependency` on locked replay: the lock supplies the complete install list.
For explicit preloading, use ordered, target-scoped flags such as
`--preload aws=httpfs --preload iceberg=httpfs --preload iceberg=aws` during discovery.
These dependencies are installed **and loaded in the stated order** before their target;
install-only dependencies are a separate mechanism. Replay uses locked `load_names`
and rejects `--preload` overrides. This preserves the actual capture environment when,
for example, an exploratory AWS capture explicitly preloaded HTTPFS even though AWS's
initializer did not load it itself.
Output directories must be new, so candidate captures cannot overwrite a baseline.

### Isolation, downloads, and failures

Collection currently requires POSIX. Every extension attempt runs in a fresh process
with an empty temporary HOME, working directory, secret directory, and extension store.
The child inherits an allowlisted environment, without authentication tokens, cloud
credentials, proxies, Python/loader overrides, or the user's installed extension store.
Python `-I -B` disables user-site imports and bytecode writes, including imports from
the repository's `scripts/` directory outside temporary HOME. Autoload and autoinstall are disabled
throughout catalog enumeration; persistent secrets, unsigned binaries, and community
signatures are disabled. Only the chosen extension and ordered explicit preloads are
explicitly loaded. If native
initialization requires an absent registered dependency, discovery starts a fresh
attempt with that dependency explicitly installed first (at most 16 dependencies).
Explicit/native dependency loads are attributed from `duckdb_extensions()`; automatic
downloads remain disabled. Locked replay cannot discover or download an unpinned dependency.

The downloader accepts only exact engine-ABI/platform/name HTTPS URLs under
`https://extensions.duckdb.org` (`--repository core`, default) or
`https://nightly-extensions.duckdb.org` (`--repository core_nightly`, explicit).
There is no fallback to another engine, repository, or community source. Redirects
and proxy discovery are disabled. Names such as `postgres` and `sqlite` resolve using
the running engine's registry aliases. Discovery records compressed-download and
uncompressed-binary SHA-256, binary size, exact URL, repository, and the engine-reported
extension version for every downloaded prerequisite and target. Local `INSTALL`
preserves engine metadata checks, and `LOAD` retains official signature checks.
Locked replay verifies downloaded bytes **before installation or loading**, checks
installed bytes/version, and matches the full observed engine identity, including the
native Python module hash. Unavailable artifacts remain explicitly incomplete; a lock
with no artifact does not authorize a later download. Discovery is exploratory trust
on first download; only the second pass establishes reproduction of those pins.

The collector invokes no extension functions, UI/server startup commands, authentication,
or external `ATTACH`. MotherDuck is downloaded and installed when available but **never
loaded**: its proprietary initialization has no reviewed offline contract here. It is
reported as `skipped` with `motherduck_load_requires_offline_review`, without supplying
a token or connecting to its service. Native extension initialization still executes
trusted signed code; process/store isolation is not an OS network sandbox.

`--timeout 180` bounds each attempt, including downloads and native loading. Timeouts,
crashes, unavailable binaries, and load failures are recorded per extension and do not
abort subsequent extensions. Process groups are terminated and temporary stores removed.
Checkpoints preserve downloaded artifact provenance even when native loading crashes.
Errors contain phase, stable code, exception type or HTTP/exit status; arbitrary native
exception text/stdout/stderr is discarded to avoid writing tokens or personal paths.
Exit status is 1 if any extension is incomplete (including a deliberate skip), and 0
only if every selected capture succeeded. Inspect `summary.json` after either result.

### Collector output schema (version 2)

Every base, extension, lock, and summary identifies
`capture_protocol: "gatekeeper-isolated-staged-capture-v2"`. Legacy schema-v1 exports
and adapters are rejected as replay locks: recapture them with this collector. The
summary records the collector source SHA-256 and `evidence_kind` as
`collector_discovery` or `collector_locked_replay`. Previously exported exploratory
raw captures remain separate historical evidence; converting their JSON shape does
not establish that the collector replayed them. Protocol labels are provenance
claims, not cryptographic attestations of who ran the tool.

- `base.json`: `snapshot_type: "base"`, `engine`, `loaded_extensions`, and the full
  qualified `functions` list from `audit_inventory.capture_functions`. Engine identity
  includes library version, source ID, codename, Python/package versions, platform,
  extension ABI directory, and native-module SHA-256. Statically linked extension
  provenance is covered by this engine hash, rather than an invented downloaded artifact.
- `<inventory-name>.json`: `snapshot_type: "extension_delta"`, `inventory`,
  `resolved_name`, `base_sha256`, `mode` (`discovery`/`verified`), `status`, `phase`,
  `attempts`, `install_names`, ordered `load_names`, `artifacts`, and, on success, `initial_extensions`,
  `loaded_extensions`, `dependencies_loaded`, `function_count`, and `functions`.
  Early failures can omit fields not yet observed. `functions.added` and
  `functions.removed` contain complete signature rows for added/removed qualified
  identities; `functions.changed` contains `{before: [...], after: [...]}` overload
  groups for an existing identity whose signatures changed. Identities use exact
  catalog, full schema path, name, and kind. Reconstruct the full snapshot by removing
  removed rows and changed-before groups from the base, then adding added rows and
  changed-after groups. The delta includes registrations from loaded dependencies;
  the loaded list records attribution candidates, not proof of individual function ownership.
  `stages` records `before`, each explicit `dependency` load, and `target`, retaining
  loaded-extension observations and a full-function-content hash at every stage.
  Each load stage includes a delta relative to the previous stage; the target stage
  thus excludes registrations already observed after explicit preloads. Native
  dependencies loaded by the target remain attributed to that target stage and its
  loaded list. `stages_sha256` pins the ordered stage observations; replay fails if
  preload order, dependency registrations, loaded versions, or target signatures differ.
- `lock.json` (discovery): `schema_version`, `engine`, `base_sha256`, and `extensions`
  keyed by inventory name, each with `repository`, `resolved_name`, `install_names`,
  ordered `load_names`, `artifacts`, discovery `status`, and `stages_sha256` (null
  for incomplete captures). A successful lock requires staged evidence and cannot
  claim MotherDuck was loaded. A skipped MotherDuck result has no function snapshot
  or completed target stage. Linked builtins appear in the load plan as needed,
  retain engine-hash provenance, and never acquire invented downloaded hashes.
  All hashes are SHA-256; JSON-content hashes use sorted keys and compact separators
  with Python's default ASCII escaping. This lock pins binaries, not classifications.
- `summary.json`: collection mode, protocol/source identity, base hash, and per-extension statuses.
  `mode: "verified"` means a locked replay was attempted; only `status: "ok"`
  establishes a successful artifact-and-stage verification. A base
  failure instead produces `base-failure.json` and prevents extension collection.

Candidate JSON outputs can be checked in intentionally as runtime evidence. Keep the
shared base once per engine and compact per-extension deltas rather than duplicating
the core catalog for every extension. Historical baselines and review provenance remain
separate; collection never creates grants or reclassifies functions. The existing
`audit_inventory.py` interface retains its no-automatic-install behavior.

## Repinning the engine

Our submodule and release toolchain pins make local/CI artifacts reproducible. They do
not prevent community rebuilds against another engine: grammar and serializer code
come from the engine being compiled, and DuckDB checks each binary's compatibility.
Compilation and regression tests establish source compatibility; unsupported structures
still fail closed. No inventory re-review is required just to rebuild against a patch
or minor release. To change our release build defaults, update together:

- the `duckdb` submodule and engine version/revision in `versions.cmake`
   (release build metadata; not an engine allowlist). The workflows read the pin from
   there through a metadata job (`scripts/versions.py`): the `OVERRIDE_GIT_DESCRIBE` label
   in `test.yml`, the reusable pipeline's `duckdb_version` and artifact names in
   `MainDistributionPipeline.yml`, and the stamp checks follow it without an edit. The
   `Makefile` and `scripts/engine.py` read it too and apply it only when the engine checkout
   is at exactly the pinned revision;
- `ci_tools_version` and the reusable workflow ref in
  `.github/workflows/MainDistributionPipeline.yml`, plus the `extension-ci-tools`
  submodule (upstream tracks each minor release on a codename branch such as
  `v1.5-variegata` rather than tagging patch releases);
- the `duckdb` pin in `requirements-dev.in` and the regenerated hashed lock files
  (`uv pip compile`, see [CONTRIBUTING.md](../CONTRIBUTING.md#dependencies));
- the fuzz image (`test/fuzz/Dockerfile`), whose venv installs the same lock file;
- the DuckDB-Wasm runtime and npm lock in `test/wasm` and the Emscripten pin in
  `scripts/build_wasm.py`. The npm package version differs from the engine it embeds; the EH
  browser test asserts the embedded engine against the pin in `versions.cmake`, so a runtime
  that embeds another engine fails there;
- the hosts of the distribution workflow's loadable legs that are not the pinned Python package
  (`env` of `.github/workflows/MainDistributionPipeline.yml`): the musl CLI is the engine's own
  release asset and follows `versions.cmake` without an edit, but the CRAN `duckdb` package that
  loads the MinGW artifact is pinned through `R_CRAN_SNAPSHOT`, a dated Posit Package Manager
  snapshot, which must move to a date after CRAN published the R package of the new engine
  version, with `R_VERSION` set to an R release for which that snapshot serves Windows binaries
  (Posit Package Manager builds them per R minor version). Both legs assert the
  host's engine version, so a stale snapshot fails rather than tests the wrong engine. The CLI
  smoke (`scripts/smoke_cli.sh`) reads audit records from the engine's `stdout` log storage and
  matches its rendering of the record; check those patterns on the new engine;
- the benchmark table in the README and the community descriptor, regenerated with
  `scripts/benchmark.py --markdown` on the new engine. Its footnote names the engine and
  extension version it was taken on, and `test_documentation.py` checks that against the pin;
- the parser-specific expectations of the Python suite's PEG leg (`GATEKEEPER_PARSER=peg`,
  see [CONTRIBUTING.md](../CONTRIBUTING.md#testing)): every `by_parser(...)` site, the
  `PEG_DEEP_NESTING_CRASH` skips, and the enablement path in `test/support/artifact.py` state
  facts about the pinned engine's PEG parser and are re-derived, not carried. The checklist is
  [#90](https://github.com/nozzle/duckdb-gatekeeper/issues/90);
- when the pin crosses into DuckDB 2.0, the 1.5 side of the dual-engine build: every
  `#if GATEKEEPER_DUCKDB_MAJOR` branch in `src/`, every `by_engine(...)` and `ENGINE_MAJOR` site in
  the Python suite, the 1.5 label derivation in `scripts/check_engine_stamp.py`, the 1.5 row of
  `compatibility.yml`'s matrix, and the `code IN ('parser', 'unsupported')` assertions in
  `test/sql/statements.test` that hold on both engines. Each is deleted or tightened to the 2.0
  fact, not carried. The checklist is
  [#99](https://github.com/nozzle/duckdb-gatekeeper/issues/99).

Historical inventory source references and baselines need not change with the build pin.

The CI inventory report runs on every push/PR. A manually dispatched candidate-version
job captures and uploads a report against the historical baseline. Neither promotes
names automatically. Compatibility CI additionally builds a separate pinned engine
checkout and runs the SQL contract suite against it.
