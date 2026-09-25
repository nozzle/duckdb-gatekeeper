# Changelog

User-visible changes to Gatekeeper, newest first. Each release section becomes the top of that
release's GitHub notes (`scripts/package_release.py`), so entries are written for the host
integrating the extension, not for the commit log. Engine pins are in `versions.cmake`.

## Unreleased

### Changed

- **Breaking (#108):** `allowed_functions` is now a list of qualified grants
  `{catalog?, schema_path, name, type?}` in typed options, canonical settings, and JSON policy v2.
  String grants are rejected with migration guidance. Catalog/schema wildcards follow table rules;
  the leaf is exact (`*` is multiplication). Optional kinds are scalar, aggregate, table, macro,
  table_macro, and window. Both policy layers authorize resolved entries before callbacks on the
  private binder's catalog path. Defaults grant reviewed `system.main` identities only; host shadows
  and `system.pg_catalog` compatibility macros need explicit grants. Reviewed grant aliases apply
  only to their system implementations; blocks remain alias-canonicalized leaf-wide denies.
- Function evidence preserves known qualified identities, including 2.0 window functions. Unknown
  caller implementation identities fail closed. Selected 1.5 aggregate specializations may retain
  an unambiguous system definition recorded by the same authorizing bind; see
  [qualified-function feasibility](docs/qualified-functions.md) for its scope and engine-hook limits.
- Caller-written list aggregate dispatch requires a literal aggregate name authorized as a
  `system.main` aggregate before private binding. Computed/parameterized target names are refused.
  Caller `COLLATE` is refused on 1.5 because its direct-bound scalar implementation has no reliable
  catalog provenance. Trusted macro/view bodies retain their existing trust. Replacement readers
  are resolved and pinned before reader binding; implicit helper shadows are refused even if granted.

- Lakehouse integration uses digest-pinned RustFS 1.0.0 for its disposable S3 fixture,
  replacing MinIO's image after its registry stopped allowing anonymous pulls.
- **Breaking:** table policies, canonical settings, validation results, and audit identities replace
  `schema VARCHAR` with `schema_path VARCHAR[]`, outermost schema first. JSON policies now require
  version 2 and use `docs/policy-v2.schema.json`; version 1 and the old `schema` field are rejected.
  DuckDB 2.0 nested schemas are supported with full-path authorization and provenance; 1.5 uses
  one-element paths. Path wildcards match one component at exactly the specified depth, never
  recursively. Migrate `schema: 'reporting'` to `schema_path: ['reporting']`; `['*']` covers only
  top-level schemas.
- Replacement-scan violations now report the full written path in `table` (for example,
  `s.file.csv`), rather than only its leaf name, with `catalog = ''` and `schema_path = []`.
  Written qualifiers are not resolved catalog identities; pre-bind refusals likewise leave
  catalog/schema identity empty.

- Every distributed artifact is now loaded, as the loadable it is, into an official DuckDB host
  of the pinned engine and exercised across the host/loadable ABI boundary before a release is
  published: the Python package on Linux, macOS, and Windows (both architectures each, now with
  the full test suite on Windows too), the engine's musl CLI in Alpine for the two musl builds,
  the CRAN R package for the MinGW build, and Chromium for Wasm EH. Previously the musl and
  MinGW artifacts were only tested statically linked. The portable form of those checks is
  `scripts/smoke/*.sql`. (#103)
- The `wasm_threads` (COI) exclusion is now documented against its cause, a link-flag bug in
  the upstream toolchain that leaves every `wasm_threads` extension unloadable, with the exit
  condition in [#101](https://github.com/nozzle/duckdb-gatekeeper/issues/101). (#103)

### Known

- On the DuckDB 2.0 alpha, an expression that reads `warnings` after `enforced` from the same
  `gatekeeper_enforce()` row mis-evaluates; read the columns separately or use `CALL`. Release
  binaries target 1.5.5, which is unaffected.
  See [Compatibility and review](docs/security.md#compatibility-and-review) and
  [#102](https://github.com/nozzle/duckdb-gatekeeper/issues/102).

## 0.3.0 - 2026-09-23

### Added

- `caller_objects` is appended to validation results and included in audit decisions. It lists
  the resolved catalog tables/views attributable to the caller, separately from the transitive
  `objects` evidence, and is empty on any failed decision. It supports checking declared inputs
  without admitting a view's ancestors. Attribution retains the conservative query-wide name
  rules; macro and reader capabilities are not catalog inputs. Named-column consumers are
  unaffected; positional `SELECT *` consumers must accept the extra column. (#95)
- Both `gatekeeper_configure` and `gatekeeper_validate` accept `json := document` as an
  alternative to typed options for shared policies. JSON and typed options are mutually
  exclusive; decoded options retain the same replacement, validation, and global-ceiling
  semantics. The versioned document has a published authoring schema at
  [`docs/policy-v1.schema.json`](https://github.com/nozzle/duckdb-gatekeeper/blob/v0.3.0/docs/policy-v1.schema.json). (#94)
- The same source builds against DuckDB 2.0 (`v2.0-cyanoptera`) as well as the pinned 1.5.5, and
  the test suite runs on either engine. Release binaries still target 1.5.5. Decisions are the
  same on both engines; where the engine itself changed, Gatekeeper follows it, and
  [Compatibility and review](docs/security.md#compatibility-and-review) lists what a host on 2.0
  sees differently: `SHOW name` is unsupported there (it can read a setting at bind time), DML
  inside a CTE and nested schema paths (`a.b.c.name`) are `unsupported` rather than parser errors,
  and 2.0's lazy `SELECT` results are accounted for: `gatekeeper_enforce` and
  `gatekeeper_configure` run when their statement runs under every spelling, read or not. The
  engine-rebuild workflow builds against a 1.5 and a 2.0 candidate and, besides the SQL contract,
  runs a native probe holding a prepared statement handle across a policy change on each. (#98)

### Fixed

- The load-time engine guard is compiled into the loadable under Gatekeeper's own build marker
  rather than a DuckDB build define that 2.0 no longer sets; a 2.0 build would otherwise have
  shipped without the guard. (#98)

## 0.2.0 - 2026-09-21

### Added

- **Enforced connections.** `CALL gatekeeper_enforce()` makes DuckDB itself refuse, on that
  connection only, anything the global policy denies; denials are `Permission Error`s the
  statement never recovers from, the transaction survives, and the latch is permanent for the
  life of the connection and unreachable from SQL. The row carries `warnings` naming host
  settings that weaken the sandbox. Enforcement is per connection; there is no instance-wide
  switch. (#45, #51)
- **Audit log.** Every decision on an enforced connection and every `gatekeeper_validate` call
  is a structured record of DuckDB's own logger under the `Gatekeeper` log type:
  `CALL enable_logging('Gatekeeper')`, read with `duckdb_logs_parsed('Gatekeeper')`. Denials
  and policy changes are `INFO`; allowed decisions are `DEBUG`
  (`SET logging_level = 'debug'`). Records carry the `gatekeeper_validate` columns plus
  `event`, `mode`, `boundary`, `statement` (capped at 64 KiB), `statement_length`,
  `policy_hash`, and `new_value`. (#50)
- **Log-only mode.** `SET gatekeeper_log_only = true` makes enforced connections record every
  decision (`mode = 'log_only'`) and refuse nothing, for seeing what a policy would refuse
  before it refuses anything; `false` restores refusals at the next statement. Global,
  BOOLEAN, frozen by `lock_configuration`, recorded as `log_only_changed`. (#52)
- **Dynamic `PIVOT`** (no `IN` list) is decided identically by `gatekeeper_validate` and
  enforced connections, as the statements DuckDB rewrites it into. (#54)
- A Benchmarks section in the README and the community descriptor, regenerated by
  `scripts/benchmark.py --markdown`. (#79)

### Changed

- **Trusted views, macros, and attached tables are opaque to table policy.** A host view, scalar
  or table macro, or attached-catalog table or view is authorized by its own identity: the caller
  must be allowed to name it, and what its definition reads is its own, exempt from
  `allowed_tables`, from `blocked_tables`, and from the internal-object rule alike. Allowing a
  view no longer requires allowing every table behind it, and a block on such a table no longer
  reaches the views and macros that read it; block the view or macro itself to withdraw it.
  What the caller's own text names is the caller's wherever it binds, so `FROM v JOIN t` is
  still checked on `t` when `v` reads `t`, and a CTE or table the caller names that shares a name
  with what a definition reads is checked as the caller's too (rename the CTE to lift it).
  `objects` still lists every table and view read. A host definition that derives a table name
  from a caller argument (`query_table(n)` in a macro body) delegates table selection to the
  caller through that capability. Statements denied by table policy can still be prepared;
  their execution is refused at the `authorize` boundary. The execution boundary holds the engine's
  plan to the sources the validated statement scanned, base tables by identity and table
  functions by name, each by count. A relation whose query node introduces a source or extra
  scan absent from its SQL rendering is refused as a `statement` violation; a same-source,
  same-count substitution remains indistinguishable, as documented in the security model. (#91)
- **Trusted views, macros, and attached tables are opaque to function policy.** What their
  definitions introduce is exempt from the allowlist, from `blocked_functions`, and from the
  never-bind list alike, apart from Gatekeeper's own control plane; 0.1.2 applied
  `blocked_functions` inside them. The same function written by the caller next to the view
  is still the caller's. A caller's `FROM 'file.parquet'` inside a trusted view is the view's
  reader, as `read_parquet('file.parquet')` already was. (#55)
- **`enable_logging`, `disable_logging`, and `truncate_duckdb_logs` are never-bind.** They were
  `elevated` (grantable by name) in 0.1.2; a host that granted them can no longer, since
  `enable_logging(storage := 'file', ...)` is a file-write primitive that redirects the
  operator's sink and the other two erase the trail. (#50)
- An enforced connection's audit record of a parser error carries the position and message
  `gatekeeper_validate` reports for the same text, and when a function occurs more than once
  in a statement the earliest position is the one reported, on every path. (#67)
- `CALL gatekeeper_enforce()` inside a transaction the host has opened is refused with a
  `Permission Error` and latches nothing: an enforced connection could never `COMMIT` or
  `ROLLBACK` it. The host's transaction stays usable; enforce after ending it. (#82)
- A duplicate or malformed option to `CALL gatekeeper_configure(...)` is a `Binder Error`, as it
  is for `gatekeeper_validate(...)`; it was an `Invalid Input Error`. (#82)

### Fixed

- `scripts/audit_inventory.py --load-extension` loads the named file whether or not it is
  signed. (#78)

## 0.1.2 - 2026-09-15

### Fixed

- A list lambda body that cannot be inspected fails closed instead of being admitted. (#43)
- Engine identity stamping is gated on the pinned revision, so a rebuild against another
  checkout keeps that checkout's own identity; each binary refuses to load into an engine it
  was not built from even when DuckDB's footer check is disabled. (#41, #42)

## 0.1.1 - 2026-09-14

### Changed

- The source can be rebuilt by the community repository against DuckDB versions other than the
  release pin; compatibility is established by builds and regression tests rather than a fixed
  release allowlist. (#40)

## 0.1.0 - 2026-09-14

First release: `gatekeeper_validate` decides one read-only statement against a lockable global
policy (`CALL gatekeeper_configure`, `gatekeeper_policy`) with request-layer narrowing; table
allow/block rules with wildcards; a reviewed default-function inventory with allow/block lists
and a never-bind list; replacement scans decided before any reader binds; DuckDB 1.5.5 builds
for Linux, macOS, Windows, and Wasm EH.
