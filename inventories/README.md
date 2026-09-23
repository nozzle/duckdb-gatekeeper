# Reviewed function inventories

Gatekeeper owns its function classifications here:

- `core.json`: built-in groups (operators, aggregates, windows, syntax helpers,
  generators, scalars), default compute names, and excluded names.
- `extensions/*.json`: one file for each reviewed core extension, preserving
  `compute` and `elevated` groups, implementation source links, and review notes/pins.
- `baselines/duckdb-1.5.5.json`: runtime signatures and loaded-extension versions
  captured from the pinned Python DuckDB runtime. This includes Python-specific
  functions; it does not claim that all extensions were loaded or audited live.

Types, casts, and collations are supplied by the database owner and have no
Gatekeeper allowlist or mandatory inventory audit.

## Adjusting defaults

Move exact normalized names between `compute` and `elevated` after source review.
Only compute names are compiled into defaults. If a core function moves, update
its descriptive `groups` membership too. `unreviewed` records baseline names without
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

Function policy matches names. Existing DuckDB implementations are trusted across
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
   they are never added to defaults by enumeration.

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
