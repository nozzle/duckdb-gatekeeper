# DuckDB 1.5.5 macOS ARM64: compact verified runtime evidence

**Final locked replay: 28 successful extensions, MotherDuck skipped; all 29
inventories attempted.** Engine `v1.5.5`, source ID `d8cdaa33fd`, codename
`Variegata`, platform `osx_arm64`, Python package `1.5.5`. See
[summary.json](summary.json) and [collection.json](collection.json).

## Final versus preliminary outcomes

The final records use `scripts/capture_extensions.py` schema 2, protocol
`gatekeeper-isolated-staged-capture-v2`, in **verified** mode. They are actual
locked replay results, not adapters labeled as verification. The preceding
protocol-v2 discovery generated the lock, including explicit ordered
`load_names`, separate `install_names`, artifact hashes, and stage hashes.
All 28 successful captures matched their locked registration and metadata stages.
There were no crashes or timeouts. MotherDuck installed with verified artifact
hashes but its LOAD was skipped by the collector; runtime coverage is incomplete.

**Correction to preliminary ODBC evidence:** the old explorer requested
`odbc.duckdb_extension.gz`, which returned 404. The engine registry resolves
`odbc` to **`odbc_scanner`**. The correct official binary downloaded and loaded
successfully in both final discovery and locked replay. Its footer reports the
stable C ABI `v1.2.0`, extension version `274a330734`, and platform `osx_arm64`;
this is not a 1.5.5 engine-version mismatch.

The earlier exploratory run had 27 successes, one ODBC URL failure, and one
MotherDuck LOAD failure. Those outcomes remain explicitly labeled in
`original-evidence.json`. MotherDuck's exploratory LOAD tried to fetch
`api.motherduck.com/extension_version`; the macOS network-denying sandbox blocked
contact. No credential, authentication, attachment, or successful service contact
occurred. **Final discovery and replay never invoked MotherDuck LOAD.** The
exploratory Iceberg missing-Avro and UI missing-directory failures also remain
recorded, along with their successful fresh-process retries.

## Compact layout and reconstruction

- `base.json`: the **only full function array**, shared by all final captures.
- `<inventory>.json`: all 29 final collector outcomes. Successful records contain
  dependency/target stage deltas and metadata plus the collector's aggregate
  base-to-after delta. `stages_sha256` binds the ordered stages.
- `lock.json`: genuine protocol-v2 discovery lock used for the final replay.
  `load_names` explicitly orders dependency preloads followed by the target.
- `summary.json`: final statuses, collector source hash, base hash, and mode.
- `report.json`: one aggregate source-map report and compact per-extension
  findings. The aggregate is a union of independently observed registrations,
  not a claim that all extensions were loaded together. Missing defaults are
  listed once. Per-target findings exclude dependency and base registrations.
- `original-evidence.json`: exact metadata and hashes for **37 original full
  snapshots (23 distinct function arrays)**, references to their final
  reconstructible function arrays, preliminary artifact metadata, and outcomes.
  There are no duplicate exploratory full snapshots or raw/adapter trees.
- `collection.json`: engine/native-module provenance, preliminary and final
  isolation descriptions, artifact footer supplement for corrected ODBC, input
  hashes, and original size for comparison.
- `reconstruct.py`: offline, standard-library-only reconstruction and validation.

Run from the repository root:

```sh
python inventories/runtime/duckdb-1.5.5-osx_arm64/reconstruct.py
```

This verifies all final outcomes, artifact records against the lock, ordered
stage hashes, and **65 final registration stages**, then reconstructs all 37
original full-file SHA-256 values exactly. `functions_ref` identifies either the
shared base, an extension's aggregate delta, or `name.json#stage=N` (zero-based,
inclusive). Apply added/removed/changed signature groups as a multiset; preserve
duplicate overload rows. Sort reconstructed rows by `json.dumps(row,
sort_keys=True)`, combine them with the preserved exact metadata, serialize with
`indent=2, sort_keys=True`, and append one newline. The result matches the
original full snapshot byte hash, including sanitized original metadata paths.

The original 188-file tree occupied **36,322,064 bytes / 1,835,558 lines**.
Compaction removes approximately **95%** of its bytes and lines. Only the new
exploratory duplicates were removed; `inventories/baselines/duckdb-1.5.5.json`
and the historical classifications/default map retain their original hashes.

## Substantive observations

- **`system.main.vortex_version`**, kind **macro**, zero arguments, body
  **`'0.86.1'`**, is the only added name absent from all historical classifications.
  The Vortex artifact footer/version is `9a8eb67`. No permission was added.
- INET adds scalar overloads to `system.main.+` and `system.main.-`.
- Spatial adds a scalar overload to `system.main.st_astext`. Raw registration
  case is preserved, while source-map identity comparisons normalize case.
- No target-added default-name identity falls outside the source-backed grants.
  The report retains known synthetic 1.5.5 window-as-aggregate reporting rows
  without granting aggregates or changing their raw labels.
- ICU, JSON, Parquet and `core_functions` are already linked into the clean
  Python base. Their executed provenance is the hashed native Python module;
  downloaded ICU/JSON/Parquet artifacts are supplementary provenance, not claimed
  as executed implementations. A base/dependency registration is not target
  ownership. Explicit preloads are setup choices, not proof every dependency is
  mandatory for LOAD.

All successful preliminary artifact downloads retain compressed/decompressed
hashes and footer metadata. Final non-base artifact hashes and installed
versions are verified against the lock. The corrected ODBC footer/hash supplement
is in `collection.json`. The historical MotherDuck proprietary implementation
binary is distinct from the repository artifact observed here; no historical
implementation provenance is inferred from its loader.

## Reproduce the locked replay

With the exact Python runtime/native module recorded in `base.json`, from the
repository root (choose a new ignored output directory):

```sh
python scripts/capture_extensions.py collect --allow-install \
  --python /path/to/matching/venv/bin/python \
  --output build/inventory-release/replay-new \
  --lock inventories/runtime/duckdb-1.5.5-osx_arm64/lock.json \
  --timeout 90
```

The collector returns nonzero for incomplete coverage, including the intentional
MotherDuck skip. Inspect all entries in `summary.json`; do not reinterpret a
skip as a successful capture. Downloads use exact official engine/platform URLs,
without redirects or proxy discovery. Each extension runs in a fresh process,
database, HOME, temporary directory, and extension store with a credential-free
environment; automatic install/load and persistent secrets are disabled. No
external databases, auth services, or UI functions are invoked. The final
collector does not claim the preliminary explorer's network-denying OS sandbox.

## Validation

Exact reconstruction and final lock/stage verification passed. The original
27 successful post-load arrays match final replay byte-for-byte at the function
array level; ODBC adds newly available runtime coverage. Build/generation and
inventory audit checks use the pinned engine source in the main checkout.
The earlier full-suite run had 1,645 passed, 54 skipped, 2 xfailed and seven
tooling failures due to the worktree's uninitialized DuckDB submodule. Updated
compaction validation results are recorded in `validation.json`.
