# Reviewed function inventories

Gatekeeper owns its function classifications here:

- `core.json`: built-in groups (operators, aggregates, windows, syntax helpers,
  generators, scalars), default compute names, and excluded names.
- `extensions/*.json`: one file for each reviewed core extension, preserving
  `compute` and `elevated` groups, source links, and migrated review notes/pins.
- `baselines/duckdb-1.5.5.json`: runtime signatures and loaded-extension versions
  captured from the pinned Python DuckDB runtime. This includes Python-specific
  functions; it does not claim that all extensions were loaded or audited live.

The initial classifications came from Mosaic `functionset` at `3eb74ea8` (NOTICE).
Gatekeeper maintains them independently. Normal builds do not need Go or Mosaic.
The migration helpers are historical tooling, not an update mechanism.

## Adjusting defaults

Move exact normalized names between `compute` and `elevated` after source review.
Only compute names are compiled into defaults. If a core function moves, update
its descriptive `groups` membership too. `unreviewed` records baseline names that
were absent from the imported review; these remain excluded and must not be promoted
automatically. Unreviewed is not a claim of elevated behavior.

`scripts/inventory.py` checks version/source metadata, sorting, duplicates, and
classification conflicts, including conflicts across extensions. The build consumes
this same loader. Tests exercise every default and every excluded name.

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

The CI audit runs on every push/PR. A manually dispatched candidate-version job
captures and uploads a report against the existing baseline, deliberately failing
when review is needed. Snapshot generation is not approval. Semantic changes with
unchanged signatures still require source review; an empty diff is not a safety proof.
