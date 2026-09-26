# DuckDB 2.0 candidate collection

Engine: Python `2.0.0.dev2609221243`, DuckDB `v2.0.0-alpha42986`, source
`d4e72566aa8dcb35fc727e2a5ced8e9a2f6d8143`, platform `osx_arm64`.

Actual protocol-v2 discovery and locked replay covered all **29** inventories:
**25 verified successful setups** (**22 dynamically loaded** targets and **3 already
linked** targets: ICU, JSON, Parquet), and **4 unavailable** targets (Lance,
MotherDuck, UI, Vortex). `core_functions` was also initially linked.
The initial capture contains **3,207 signatures**. The union of the independent
successful captures contains **3,667 signatures / 1,438 qualified identities**.

## Evidence and attribution

- `base.json` retains the complete initial qualified catalog and exact engine identity,
  including the native Python module's SHA-256.
- Each `<inventory>.json` is byte-identical to the actual final reusable collector's
  schema-2 replay output. `functions` is the complete change from the initial base;
  the last entry of `stages` is the target-only delta after all explicit dependency
  stages. Avro and AWS functions are not attributed to Iceberg. Stage hashes bind
  the loaded-extension metadata, ordered deltas, and reconstructed function arrays.
- `evidence/<inventory>.json` retains requested/final download URLs, HTTP outcomes,
  compressed/decompressed SHA-256, the parsed footer, source descriptor and full
  revision, plus hashes/URLs for the engine's extension patches. Engine descriptors
  and footer source prefixes agree for every available out-of-tree extension.
- `lock.json` is the actual protocol-v2 discovery lock used for replay. It records
  separate `install_names` and ordered `load_names`, artifact hashes, and stage hashes. The
  downloaded linked-extension archives are additional provenance evidence, not the
  binaries executed by Python. Their initial runtime registrations remain in `base.json`.
- `summary.json`, `collection.json`, `report.json`, and `evidence/validation.json`
  record coverage, isolation, drift, and integrity checks.
- `evidence/discovery.json` preserves compact discovery outcomes and hashes without
  duplicate catalogs. `evidence/preliminary-observations.json` labels the earlier
  exploratory metadata and failure observations separately from final outcomes.

Final captures were made by `scripts/capture_extensions.py` at `a786b9b`, protocol
`gatekeeper-isolated-staged-capture-v2`, and retain its exact source hash. Native
loads used fresh processes, in-memory databases, HOME and extension/secret directories,
an allowlisted environment, Python `-I -B`, and disabled automatic install/load.
DuckDB's signature and metadata checks remained enabled. The final collector does
not use the preliminary explorer's macOS network-denial sandbox. No external
connection, attachment, authentication, or server-starting functions were invoked.

## Availability and load outcomes

All available binaries came from
`https://extensions.duckdb.org/v2.0.0-alpha42986/osx_arm64/`.
Final discovery requested each unavailable target and received HTTP 404. Locked
replay returned `artifact_not_in_lock` for those targets without repeating their
downloads or reaching LOAD. Lance's HTTPFS prerequisite was downloaded and installed
before replay reached the missing target; it was not loaded. The preliminary
version and `d4e72566aa` archive paths and matching `linux_amd64` probes also returned
404. These retained observations are evidence of
unavailability for these exact archive coordinates, not proof of universal platform
support or lack of it.

- **Lance:** the candidate engine's extension descriptor comments out its build.
- **Vortex:** its descriptor defaults `VORTEX_ENABLED` to OFF while CopyFunction changes.
- **MotherDuck and UI:** no matching artifact at the tested coordinates. Neither
  entrypoint was loaded; MotherDuck was unavailable rather than skipped or an
  authentication/load failure.
- **Iceberg:** final discovery and locked replay both succeeded with ordered
  `httpfs → aws → avro → iceberg` loads (**35** target-added signatures). The old
  missing-Avro error and successful minimal-preload retry are retained as preliminary
  observations, not final replay failures. Other explicit final setups are
  `httpfs → aws`, `httpfs → delta`, `httpfs → ducklake`, and
  `httpfs → aws → unity_catalog`. Preloads are setup choices, not proof each is
  mandatory for loading the target.
- **ODBC:** `odbc_scanner` is an engine-recognized alias. The matching archive's
  footer is `C_STRUCT / v1.2.0`, which means the stable C API version, not a DuckDB
  engine mismatch. The candidate engine's `ParseExtensionMetaData` and C API load
  dispatch confirm this interpretation; normal signed loading succeeded (**11**
  signatures). See the pinned engine's
  [`extension_load.cpp`](https://github.com/duckdb/duckdb/blob/d4e72566aa8dcb35fc727e2a5ced8e9a2f6d8143/src/main/extension/extension_load.cpp).
- **Azure and HTTPFS:** successful loads added zero captured function signatures;
  successful extension loading is distinct from adding scalar/table/etc. functions.

## Current-default reconciliation

**913 of 919** compiled default identities were observed. There were **zero** default
names at unexpected namespaces or kinds. The six unobserved defaults are explained
by pinned registration sources in `evidence/reconciliation-sources.json`:

| Identity in `system.main` | Source reconciliation |
| --- | --- |
| `icu_collate_yue`, `icu_collate_yue_cn` — scalar | ICU now enumerates `Collator::GetCollations()` from the embedded `collation_infos` array. Its 140 entries omit these locales; no alternate qualified identity was observed. |
| `round_even`, `roundbankers` — macro | The candidate registers the scalar function set and alias instead; both scalar identities are already explicit defaults. The old macro registrations are absent from `default_functions.cpp`. |
| `st_snap` — scalar | The candidate spatial descriptor pins `686950e980…`, whose GEOS registration module has no `ST_Snap`. The historical reviewed `eb1e57c9…` module explicitly registers it. This is a source-version availability difference, not an inferred namespace move. |
| `unnest` — scalar | SELECT-list UNNEST remains a binder intrinsic (`BoundUnnestExpression`), not a scalar catalog registration. Its table identity is observed. |

The report also lists **248 runtime names absent from all historical classifications**.
These include new `collate_*` sort-key functions, JSON helpers, internal engine
functions, AWS CloudFormation functions, and extension additions. They are maintenance
findings, not automatic policy additions. Existing GEOMETRY/GeoJSON function rows
present in the initial catalog are not credited to spatial merely because their names
appear in its historical inventory; the candidate engine also patches spatial's
duplicate GeoJSON registrations out.

The historical Python baseline comparison is name/signature-only: that baseline is
unqualified and loads fewer extensions. Its additions cannot all be called new 2.0
functions. This collection is a candidate, not a replacement baseline or a review of
new implementations. Historical classifications, provenance, and grants are preserved.

## Validation and reproduction

All **25 successful discovery/replay setups** have identical locked artifact records,
load plans, and stage hashes. Offline reconstruction verified **58 registration stages**,
including their initial boundaries, preserved overload multiplicity, checked artifact
hashes against the footer/source supplements, and confirmed the aggregate report is
unchanged. Final replay has **zero load failures, skips, crashes, or timeouts**; the
four unavailable results remain incomplete runtime coverage.
All 25 successful targets have the same explicit install/load plans as the final
1.5.5 collection, providing comparable loaded setups across the two engines.

From the repository root:

```sh
python inventories/runtime/duckdb-2.0-d4e72566aa-osx_arm64/reconstruct.py
```

To repeat the actual locked collection with the exact Python runtime/native module
recorded in `base.json`, choose a new ignored output directory:

```sh
python scripts/capture_extensions.py collect --allow-install \
  --python /path/to/matching/venv/bin/python \
  --output build/inventory-candidate/replay-new \
  --lock inventories/runtime/duckdb-2.0-d4e72566aa-osx_arm64/lock.json
```

The collector exits nonzero for the four unavailable targets. Inspect
`summary.json` for all outcomes. The inventory audit agrees with the regenerated
report. Historical baseline, classifications, and default-map hashes are checked
by `reconstruct.py`; full build/test validation is coordinated by the parent task.
