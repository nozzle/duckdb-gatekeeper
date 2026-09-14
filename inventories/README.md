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

`schema.json` rejects unknown keys, malformed source URLs, non-list review notes,
and invalid group shapes. The contract is: **Python's standard library is sufficient to
generate and build Gatekeeper; development tests additionally use `jsonschema` to verify
the validator.** `scripts/schema_check.py` evaluates exactly the JSON Schema keywords the
schema uses and refuses any other keyword anywhere in the schema (including `$defs` and
unselected conditional branches), so a schema edit that needs an unsupported keyword fails
clearly rather than being ignored. The test suite runs generation under `python -S`,
checks that malformed inventories are still rejected there, and cross-checks the validator
against the pinned `jsonschema` package (from `requirements-inventory.txt`) on the real
inventories and on mutated documents. `scripts/inventory.py` then checks version/source metadata,
sorting, duplicates, and classification conflicts, including conflicts across extensions.
The build consumes this same loader. Tests exercise every default and every excluded name.

The generator requires Python 3.10+ and a Git checkout with initialized pinned submodules.
`versions.cmake` owns the extension and engine version/revision; `scripts/versions.py`
reads it and derives the baseline filename. Generated C++ literals are split into
8 KB-or-smaller pieces for MSVC compatibility.

Inventory notes retain provenance, non-obvious classification traps, and coverage limitations.
Generation cross-checks implementation source URLs against DuckDB's pinned extension
descriptors or in-tree source revision. UI has an independent source pin because no
engine descriptor exists; MotherDuck records its binary version/hash in `binary_review`
and cannot contribute defaults. Original attribution is retained in `NOTICE`.

## Version update procedure

Every supported **major/minor update** requires this process; run it on patches too:

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
   or loaded-extension versions cause failure. Unknown names require explicit
   classification; they are never added to defaults by enumeration.

3. Review changed implementations and **all overloads** of each name. Record why
   non-obvious entries are default or elevated. Update source revisions and notes.
4. Capture separate baselines for optional extensions using explicit trusted local
   signed builds (`--load-extension /path/to/extension.duckdb_extension`). The tool
   never installs or auto-loads an extension on the user's behalf. Compare each
   extension against the corresponding baseline with `--baseline`.
5. Review parser/binder and serialization changes; update the build pin, grammar,
   inventory loader version, dependency versions, and tests together. Changing the
   inventory version alone cannot enable a new engine version.
6. Run the runtime audit, full conformance/default tests, build, and benchmarks.
   Replace an accepted baseline only after the review is complete.

## Repinning the engine

`scripts/generate.py` refuses to run against any DuckDB checkout other than
`SUPPORTED_DUCKDB_REVISION`, and `LoadInternal` refuses to load into any other DuckDB
release. This
is deliberate fail-closed behavior: the grammar is derived from the serializer of exactly
that revision. It also means the community repository's bulk rebuild for the next DuckDB
release fails at configure time until Gatekeeper is repinned. To repin, update together:

- the `duckdb` submodule and engine version/revision in `versions.cmake`
  (consumed by CMake, generated C++ constants, build scripts, and the audit);
- `OVERRIDE_GIT_DESCRIBE` in `Makefile` and `.github/workflows/test.yml`;
- `duckdb_version`, `ci_tools_version`, and the reusable workflow ref in
  `.github/workflows/MainDistributionPipeline.yml`, plus the `extension-ci-tools`
  submodule (upstream tracks each minor release on a codename branch such as
  `v1.5-variegata` rather than tagging patch releases);
- the `duckdb` pin in `requirements-dev.in`, the regenerated hashed lock files, the fuzz
  image, and the baseline described above.

The CI audit runs on every push/PR. A manually dispatched candidate-version job
captures and uploads a report against the existing baseline, deliberately failing
when review is needed. Snapshot generation is not approval. Semantic changes with
unchanged signatures still require source review; an empty diff is not a safety proof.
