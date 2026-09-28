# Changelog

User-visible changes to Gatekeeper, newest first. Each release section becomes the top of that
release's GitHub notes (`scripts/package_release.py`), so entries are written for the host
integrating the extension, not for the commit log. Engine pins are in `versions.cmake`.

## Unreleased

## 0.4.1 - 2026-09-28

### Changed

- Native release artifacts now target DuckDB 1.5.6. Engine source, Python lock, and
  extension-ci-tools pins move together; reviewed defaults and historical evidence are unchanged.
  See the [dependency and compatibility review](docs/release-0.4.1-validation.md), including
  runtime inventory drift and deferred updates.
- Wasm EH and Windows MinGW distribution are temporarily deferred because matching official
  Wasm/CRAN R hosts are not published. Use the v0.4.0 assets with DuckDB 1.5.5 for those hosts.
  Restore both targets only after matching hosts pass the browser/R loadable tests.

### Fixed

- Build against newer DuckDB 2.0 snapshots whose table functions use signature-based typed
  keyword arguments. Optional Gatekeeper arguments retain their ANY types, omitted-option
  semantics, and duplicate/unknown-option checks; earlier engines remain supported.

## 0.4.0 - 2026-09-28

### Added

- Append `caller_functions` to validation results and audit decisions: the sorted, deduplicated
  subset of `functions` checked by caller-scoped policy at any authorization point. Evidence
  remains empty on failure, including log-only denials. It includes implied capabilities and
  conservative attribution, not exact lexical calls. Existing validation columns keep their
  positions; audit `statement`, `statement_length`, `policy_hash`, and `new_value` move by one.
  See [evidence scope](docs/qualified-functions.md#caller-function-evidence) for unbound preflight
  names and uncatalogued helpers. Prechecked aggregate targets are included even when a NULL
  list leaves no executable aggregate in the plan. (#118)

- DuckDB 2.0 secure views now use ordinary view authorization and `type = 'view'` evidence,
  preserving the engine's optimization boundary and transitive host evidence. Validation results
  and audit diagnostics are explicitly host-only, including engine errors, `caller_functions`, and `caller_objects`:
  its conservative query-wide attribution can include hidden dependencies whose names match
  caller-written references, so it is not universally safe to expose to untrusted callers. (#114)
- A tested [Quack support matrix](docs/quack.md) covering local binding, CONNECT scope,
  independent server-session enforcement, and unsupported early remote-execution routes. (#115)

### Changed

- **Breaking:** table policies, canonical settings, validation results, and audit identities replace
  `schema VARCHAR` with `schema_path VARCHAR[]`, outermost schema first. JSON policies require
  version 2; version 1 and the old `schema` field are rejected. DuckDB 2.0 nested schemas retain
  full ancestry; 1.5 uses one-element paths. Wildcards match one component at exactly the stated
  depth; `['*']` covers top-level schemas only. Replacement refusals retain the written path
  in `table`, with no invented catalog/schema identity. See the [migration guide](docs/policy-migration.md). (#104)
- **Breaking:** `allowed_functions` and `blocked_functions` are now lists of qualified rules
  `{catalog?, schema_path, name, type?}` in typed options, canonical settings, and JSON policy v2.
  Legacy string rules and `schema` fields receive consistent actionable diagnostics; see the
  [policy v2 migration guide](docs/policy-migration.md), including typed empty lists and canonical settings.
  Catalog/schema wildcards follow table rules;
  the leaf is required and exact (`*` is multiplication); schema-wide function permission is unsupported.
  Optional kinds are scalar, aggregate, table, macro,
  table_macro, and window. Both policy layers authorize resolved entries before callbacks on the
  private binder's catalog path. Defaults contain explicit reviewed catalog/schema/name/kind identities;
  same-name functions of another kind do not inherit defaults. Host shadows and `system.pg_catalog`
  compatibility macros need explicit grants. Configurable grants and blocks match exact catalog-entry
  names without alias canonicalization, including Parquet readers, JSON extraction aliases, and window
  aliases. Cover each intended entry explicitly; Parquet file shorthand requires `parquet_scan`, not
  `read_parquet`. Scoped blocks wait for actual catalog resolution;
  blocks covering every eligible identity retain early no-bind refusal. (#113)
  - Defaults are 919 reviewed qualified identities over 913 names. Internal grants require exact
    schema components; internal table/view grants also need exact table leaves. Catalog wildcards
    remain supported, and block namespace wildcards still match internal entries.
  - Disabling defaults requires grants for default-macro dependencies and aggregate targets;
    host bodies remain opaque. Caller implementation substitutions obey blocks through casts,
    coalesce, and macros. 1.5 conservatively attributes possible replacements; 2.0 retains definitions.
  - Untrackable caller non-system native callbacks are refused (bind/extended-bind callbacks on
    1.5; expression-replacement callbacks on both). Lambda-type callbacks remain permitted.
    See [qualified functions](docs/qualified-functions.md) for provenance, first/last window
    identities, collation helpers, and quantile/list-dispatch argument restrictions.
- **Breaking:** violation STRUCTs append `function_type VARCHAR` and `object_type VARCHAR`,
  including audit decisions. Resolved refusals retain kind; unresolved/inapplicable fields are
  empty strings. All evidence lists remain empty on failure. (#113)
- Caller-written Quack SQL delegation is never-bind. Private authorization refuses opaque
  trusted expansions; deferred binding and native 1.5 preparation can execute remotely first
  and remain unsupported. 1.5 attached objects are refused; 2.0 local base-table reads require
  pushdown disabled and table provenance. Evidence is local binding scope, not remote lineage. (#115)

- DuckDB 2.0 validation now requires `system.main.getvariable` permission before caller-written
  named parameters read session variables, and reports that fixed capability as function evidence.
  Enforced 2.0 connections require that permission for named-parameter/session-variable collisions
  before binding, including explicit arguments and prepares: current hooks cannot distinguish supplied
  inputs. When granted, DuckDB preserves explicit-value precedence and Gatekeeper conservatively records
  the capability. Without permission, use a noncolliding name or positional parameter. Log-only records
  denials and lets DuckDB proceed. DuckDB 1.5 is unchanged. (#112)
- DuckDB 2.0 local enforcement activation now refuses CONNECT-ed state, including stale targets,
  when the local latch is reached. Native callback-counter regressions verify that CONNECT on a
  local enforced connection is refused before remote dispatch. Hosts must activate and keep
  enforced connections LOCAL: already-connected SQL activation and native routing-state changes
  can dispatch before Gatekeeper's hook. CONNECT/DISCONNECT remain refused even during log-only
  rollout, recorded as `mode = 'enforce'`, so SQL cannot change the routing state before the host
  restores policy refusals. Other control-plane statements keep normal log-only semantics.
  CONNECT-mode local enforcement and automatic enforcement of remote server sessions remain
  unsupported; see [host requirements](docs/security.md#connect-mode-and-native-host-state). (#111)

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

### Fixed

- Write result rows using DuckDB 2.0's per-vector cardinality API. Combining `enforced` and
  `warnings` in projections or filters now returns correct results instead of wrong answers
  or an internal error invalidating the database. Validation and configuration use
  the same row writer. DuckDB 1.5 retains its existing cardinality API. (#119, fixes #102)
- Record enforce-mode policy denials rewrapped by trusted table-macro and `query()` binding.
  Ordinary engine errors retain their existing reporting behavior.
- Bound audit statement sanitization before expanding NUL bytes, avoiding quadratic work for
  invalid input while preserving the 64 KiB UTF-8-safe prefix and original input length.
- Preserve caller attribution and written-path diagnostics for catalog-qualified replacement
  readers on 1.5. SQL named-option keys now accept mixed case; JSON keys remain case-sensitive.
- Restore the published v1 schema URL for existing release users. Historical schemas remain
  available even though 0.4.0 requires policy v2.

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
