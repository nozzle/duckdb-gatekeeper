# DuckDB 2.0 candidate collection

Engine: Python `2.0.0.dev2609221243`, DuckDB `v2.0.0-alpha42986`, source
`d4e72566aa8dcb35fc727e2a5ced8e9a2f6d8143`, platform `osx_arm64`.

All **29** inventoried extensions were attempted against the matching official
archive: **22 loaded**, **3 already linked** (ICU, JSON, Parquet), and **4 unavailable**
(Lance, MotherDuck, UI, Vortex). `core_functions` was also initially linked.
The initial capture contains **3,207 signatures**. The union of the independent
successful captures contains **3,667 signatures / 1,438 qualified identities**.

## Evidence and attribution

- `base.json` retains the complete initial qualified catalog and exact engine identity,
  including the native Python module's SHA-256.
- Each `<inventory>.json` uses the reusable collector's base/delta representation.
  `functions` is the complete change from the initial base; `target_functions` is the
  change after explicit dependency stages. `stages` preserves every boundary. For
  example, Avro's four added signatures are not attributed to Iceberg.
- `evidence/<inventory>.json` retains requested/final download URLs, HTTP outcomes,
  compressed/decompressed SHA-256, the parsed footer, source descriptor and full
  revision, plus hashes/URLs for the engine's extension patches. Engine descriptors
  and footer source prefixes agree for every available out-of-tree extension.
- `lock.json` records the artifacts actually used by successful dynamic loads. The
  downloaded linked-extension archives are additional provenance evidence, not the
  binaries executed by Python. Their initial runtime registrations remain in `base.json`.
- `summary.json`, `collection.json`, `report.json`, and `evidence/validation.json`
  record coverage, isolation, drift, and integrity checks.

The captures were made with an ignored exploratory runner and exported using
`scripts/capture_extensions.py`'s `function_delta` and `digest` helpers. Capture-function
and exploratory-runner source hashes are recorded in `collection.json`. Native loads used fresh
processes, in-memory databases, HOME and extension/secret directories, an allowlisted
environment, disabled automatic install/load, and a macOS network-denial sandbox.
DuckDB's signature and metadata checks remained enabled. No connection, attachment,
authentication, or server-starting functions were invoked.

## Availability and load outcomes

All available binaries came from
`https://extensions.duckdb.org/v2.0.0-alpha42986/osx_arm64/`.
For unavailable entries, both the version and `d4e72566aa` archive paths returned
HTTP 404. Matching `linux_amd64` probes also returned 404; this is evidence of
unavailability for these exact archive coordinates, not proof of universal platform
support or lack of it.

- **Lance:** the candidate engine's extension descriptor comments out its build.
- **Vortex:** its descriptor defaults `VORTEX_ENABLED` to OFF while CopyFunction changes.
- **MotherDuck and UI:** no matching artifact at the tested coordinates. Neither
  entrypoint was loaded; MotherDuck's absence is not an authentication/load failure.
- **Iceberg:** the first attempt failed because Avro was absent. A fresh process
  loaded Avro, captured its delta, then loaded Iceberg successfully (**35** Iceberg
  signatures). A separate exploratory run with Avro and HTTPFS also succeeded;
  the final collection uses the minimal observed dependency, Avro. The original
  missing-dependency error is retained.
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
