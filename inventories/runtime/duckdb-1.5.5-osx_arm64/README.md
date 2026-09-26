# DuckDB 1.5.5 macOS ARM64 runtime evidence

Collected **2026-09-26 UTC** using the existing Python `duckdb==1.5.5` runtime.
`PRAGMA version` returned `v1.5.5`, source ID `d8cdaa33fd`, codename `Variegata`;
`PRAGMA platform` returned `osx_arm64`. The native Python module SHA-256 is in
[collection.json](collection.json). The source ID is recorded at the exact
precision returned by the engine.

## Outcomes

All **29** inventoried extensions received an official version/platform binary
download attempt. **28** downloads succeeded, **27** target INSTALL/LOAD sequences
succeeded, **1** target LOAD failed, and **1** binary was unavailable. There were
**no crashes or timeouts**. See [summary.json](summary.json) for every outcome.

- **ODBC:** the official `v1.5.5/osx_arm64/odbc.duckdb_extension.gz` URL returned
  HTTP 404. No binary was available to install or load.
- **MotherDuck:** the signed repository artifact installed, but LOAD attempted
  `http://api.motherduck.com/extension_version`. The network-denying sandbox
  prevented contact and LOAD failed. This is **runtime-service-required,
  incomplete coverage**, not an empty function inventory. Authentication and
  attachment were never attempted. Its footer reports
  `v1.5.5-2026-09-355` verbatim; this artifact differs from the historical
  implementation binary recorded in `inventories/extensions/motherduck.json`.
  It does not establish provenance for that historical binary or its functions.
- **Iceberg:** the first LOAD identified a missing `avro` dependency. A fresh
  process/database/home with `httpfs`, `aws`, and `avro` loaded succeeded.
- **UI:** the first LOAD needed an empty `HOME/.duckdb` parent directory. A fresh
  process/database/home with that directory succeeded. No UI functions or server
  startup were invoked. Both initial setup failures are retained as
  `initial-load.json` alongside the final outcome.
- **ICU, JSON, Parquet:** already statically linked and loaded in every clean
  Python base. Their target LOADs are no-ops. Their downloaded artifacts have
  hashes and footers, but those downloads are **not** claimed as the executed
  implementations. The executed base provenance is the hashed Python native
  module. `core_functions` is also statically linked.

## Registration observations

Relative to dependency-complete pre-target snapshots, successful target LOADs
added **294 qualified identities** and **445 signature rows**, with no removed
rows. These totals sum independent process observations, not a combined catalog.

- The only added name absent from all current classifications is
  **`system.main.vortex_version`**, kind **macro**, zero arguments, body
  **`'0.86.1'`**. The Vortex artifact footer reports `9a8eb67`. This is an
  observation, not approval of a new default.
- INET adds overloads to `system.main.+` and `system.main.-` (scalar).
- Spatial adds an overload to `system.main.st_astext` (scalar). Raw Spatial
  registration case is retained; mapping comparisons normalize names to
  lowercase, matching DuckDB identity handling.
- No target-added default-name identity falls outside the source-backed grants.
  Every compute name in each successfully loaded extension's historical
  inventory was observed after loading. Presence in the pre-target snapshot is
  reported separately and is not attributed to the target.
- Full source-map reports retain the pre-existing synthetic window rows reported
  as `aggregate` on 1.5.5, and missing `window` identities. These are the known
  reporting discrepancy in `default_identities.json`, not new extension grants.

The clean base has no name/signature drift from the historical Python baseline.
That baseline is unqualified and lacks most optional extensions; comparison
against it cannot establish historical qualified extension signature drift.
Per-extension reports therefore retain both the historical comparison and the
qualified before/after comparison. Historical inventories, baseline, and default
map were not modified; their relevant hashes are recorded in `collection.json`.

## Evidence layout

- `collection.json`: engine/module identity, isolation, aliases, dependency setup,
  capture-function and historical-input hashes, special-load documentation.
- `<extension>/artifact.json`: exact official URL, final URL, UTC retrieval time,
  HTTP outcome, compressed and decompressed SHA-256 and byte lengths, all parsed
  footer metadata fields. All 28 successful downloads have complete hashes and
  footers. No download redirected to another URL.
- `<extension>/load.json`: bounded subprocess outcome, setup stages, sanitized
  diagnostics, exit code; initial setup failures are retained separately.
- `<extension>/manifest.json`: references to full base, dependency-stage,
  pre-target, and post-target snapshots where available. There is no successful
  post-target snapshot for MotherDuck or ODBC.
- `snapshots/<sha256>.json`: **37** content-addressed full snapshots, including
  all overload rows from `scripts/audit_inventory.py:capture_functions`, catalog,
  complete `schema_path`, and kind. Hashes cover the stored UTF-8 JSON bytes.
  Identical full captures share a file; each attempted load process captured its
  own base before loading. Temporary paths in extension metadata are replaced
  with placeholders; function registrations are preserved as captured.
- `<extension>/report.json`: dependency and target deltas, raw added/removed
  signatures, source-map comparison, and each loaded extension's origin.
- `collector-schema-v1/`: adapter exports matching the reusable
  `scripts/capture_extensions.py` schema: base, per-extension deltas, discovery
  lock, and summary. These were adapted from the observed full snapshots using
  its `digest` and `function_delta` helpers, not recollected by that tool.

The reusable schema's extension delta is **base to after**, so it includes loaded
dependencies. The detailed reports distinguish **base to before** (dependencies)
from **before to after** (target LOAD). Neither delta proves implementation
ownership. Collector exports use **discovery** mode; no locked replay is claimed.
The lock records only downloaded non-base artifacts; supplementary downloaded
ICU/JSON/Parquet provenance remains in their `artifact.json` files. Replaying a
dependency-sensitive observation may require the recorded explicit preload order.

## Collection constraints

Downloads came only from `https://extensions.duckdb.org/v1.5.5/osx_arm64/`.
They completed before native workers began. Each worker had a new process,
in-memory database, HOME, temporary directory, and extension store, plus an
explicit credential-free environment with empty `motherduck_token` and AWS
instance metadata disabled. Automatic extension installation/loading was off.
Only signed local artifacts were installed and loaded. Known dependencies had
their own snapshots and artifact origins.

Workers ran under macOS `sandbox-exec` with:

```scheme
(version 1)(allow default)(deny network*)(deny process-fork)
```

The network restriction was verified with a socket probe. Each worker had a
90-second limit and a separate process group. No external databases were
attached, credentials used, service connections established, or UI servers
started. MotherDuck's denied service attempt is explicitly retained above.

The exploratory collection, reporting, schema-export, and validation runners,
downloaded binaries, and isolated homes are ignored under
`build/inventory-release/`; they are not committed. Durable evidence contains
only JSON and this documentation.

## Validation

- Validated all 29 outcomes, 28 compressed/decompressed hash pairs, snapshot
  hashes, qualified row fields, engine IDs, dependency/origin references, and
  collector deltas against their full snapshots. Scanned JSON for personal or
  temporary absolute paths. Historical baseline/default-map hashes still match.
- `scripts/generate.py` passed using the main checkout's pinned engine source
  and an isolated generated-output directory.
- `scripts/audit_inventory.py --candidate <clean-base-snapshot>` passed; no
  historical name/signature drift, with expected qualified-report limitations.
- CMake build check for `gatekeeper_loadable_extension` in `build/v1` passed
  (reconfigured for new inventory evidence; compiled target was up to date).
- Full Python suite: **1,645 passed, 54 skipped, 2 xfailed, 7 failed**. All seven
  failures are in `test_inventory_tooling.py`: they directly require the
  worktree's uninitialized `duckdb/` submodule despite the external
  `GATEKEEPER_ENGINE_SOURCE` setting. Failures concern missing serialization
  fixtures/descriptors or source revision detection, not runtime evidence.
