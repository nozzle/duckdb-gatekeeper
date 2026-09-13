# Global policy design (issue #9)

Consolidated design from the Astra/Fable discussion, implemented after #13.
This is a breaking pre-1.0 API and authorization change.

## Decisions

1. **Retire the scalar mutator.** `CALL gatekeeper_configure(option := value, ...)`
   is the documented authoring API. Preserve existing named options and host-bound
   parameters. Every call builds a complete replacement from built-in defaults;
   omitted fields do not retain prior configuration. Return one true `Success` row.
   Bind validates arguments but never publishes state. Execution publishes once per
   table-function execution and checks configuration locking then, even for prepared
   statements. Plain EXPLAIN and preparation must not mutate configuration.

2. **One canonical global setting.** Register `gatekeeper_policy` as a typed STRUCT
   with a non-NULL built-in default. Include every option plus explicit BOOLEAN
   `restrict_catalogs`, `restrict_schemas`, `restrict_tables` fields. All top-level
   fields are mandatory/non-NULL. False flags mean unrestricted ordinary objects;
   true flags with empty lists deny access. Nested table/type identities retain nullable
   `catalog` (any catalog) and required nonempty `schema` and leaf names. Types and
   internal objects retain their existing explicit-permission rules.

3. **Strict authoring, explicit SET limitations.** CALL sees original argument types
   and rejects unknown top-level and nested identity fields before lossy casts.
   Direct SET accepts a complete canonical STRUCT, but DuckDB casts it before the
   callback: unmatched source fields disappear, missing target fields become NULL,
   and compatible values are coerced. Mandatory fields mitigate replacement typos,
   not extra-key typos. A misspelled nested catalog can become NULL and broaden access.
   Document CALL as the strict authoring path; SET is an integration surface with this
   limitation. Read back the normalized setting for inspection.

4. **The setting is the sole source of truth.** Do not publish a separate policy
   cache in the SET callback. Native setting APIs and registration/startup paths may
   bypass callbacks. Validation reads the global setting at execution, defensively
   decodes it, and fails closed if invalid. Each input chunk uses one coherent snapshot.
   A prepared validation sees later configuration; no policy is frozen at bind time.

5. **Global-only, replaceable, inspectable.** Configuration is per database instance,
   shared by its connections, nonpersistent and nontransactional. Replacements are
   atomic; invalid replacements preserve the old value. RESET restores built-ins.
   Register GLOBAL as the default scope, accept AUTOMATIC in the callback, and reject
   SESSION SET/RESET. Inspection must describe the same policy enforcement reads.

6. **Lock all SQL writers consistently.** CALL invokes DuckDB's CheckLock for
   `gatekeeper_policy`, the same normalization as SET, then writes the canonical setting.
   SET/RESET already check the lock. Honor DuckDB's deliberate allowed_configs
   exception equally for all writers. Bootstrap: LOAD extensions, provision trusted
   catalogs/credentials/host settings, configure policy, then lock_configuration=true.
   The setting is not discoverable for extension autoload during ordinary startup
   config. Native embedding APIs are trusted; SQL locking is not a native-code boundary.

7. **Enforce a ceiling in one pipeline.** Copy the configured snapshot, apply existing
   named request overrides to that copy, and enforce both configured and effective
   request policies at the existing authorization sites. Parse, traverse preflight,
   and bind once; both policies' preflight restrictions apply before binding. Use
   minimum limits, require both capability grants, and honor either layer's blocks.
   Evaluate qualified identities independently rather than intersecting raw sets.
   Omitted request options inherit the global policy. Otherwise valid broadening
   overrides do not raise special errors, but cannot grant access beyond the ceiling;
   mixed replacements may still narrow other access. Invalid options remain errors.
   ApplyOptions remains shared validation logic, not obsolete code.

8. **Configuration cannot be validated as tenant SQL.** Hard-deny
   `gatekeeper_configure` regardless of function or table-function options. Cover
   direct CALL, SELECT-from-function, qualified names, and resolved references inside
   views/macros. Denial must not mutate configuration or expose partial dependencies.

## Prototype findings

- Host-parameterized CALL with lists and nested identity structs works on DuckDB 1.5.5.
- SQL `PREPARE ... AS CALL` is rejected by the parser; explicit SQL preparation uses
  `PREPARE ... AS SELECT * FROM gatekeeper_configure(...)`. Both paths share binding
  and execution. SET does not accept parameters.
- Table-function parameters must be registered as ANY to preserve original types and
  nested field sets; validate explicitly and permit only integer widening for limits.
  Empty lists are accepted as empty permissions (DuckDB materializes untyped empty
  lists as INTEGER[] during table-function binding); nonempty members are checked.
  DuckDB also overwrites duplicate named options before the bind callback, so compare
  the original argument count with its named map and reject duplicates explicitly.
- Standalone CALL is recommended. Arbitrary SELECT plans can suppress table-function
  execution (e.g. an empty result plan). EXPLAIN ANALYZE executes and can mutate.
- Built-in policy is itself a ceiling even before explicit configuration. Existing
  tests/docs that granted custom functions, readers, types, file references, or higher
  statement limits per request must grant them in trusted setup first.

## Acceptance evidence

Regression coverage must exercise atomic replacement and readback across connections,
instance isolation, reset, invalid-input preservation, nullable catalog semantics,
strict unknown-key/type checks, documented SET casting, SESSION rejection, every writer
under lock and allowed_configs exceptions, prepared lifecycle, two-layer identity and
capability checks, trusted expansion denies, and configuration-function denial.
The linked fuzz harness must check native setter callback bypasses and the invariant
that clearing request blocks cannot override a configured denial. Native AST fuzzing
must check that a successful layered decision is allowed by each standalone policy.

Run release and sanitizer suites, inventory audit, formatting, lakehouse integration,
and native/linked fuzz smoke tests. Preserve DuckDB pins and reviewed inventories.
