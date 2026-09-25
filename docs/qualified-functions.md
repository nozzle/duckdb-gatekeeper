# Qualified function grants (policy v2)

`allowed_functions` accepts only STRUCT/object grants:

```sql
CALL gatekeeper_configure(allowed_functions := [
  {catalog:'system', schema_path:['main'], name:'read_parquet', type:'table'},
  {catalog:'memory', schema_path:['reporting'], name:'report', type:'table_macro'}
]);
```

Required `schema_path` is nonempty and matches exact depth. Omitted/null catalog matches any
known catalog. Catalog and schema components support whole-component `*`, not recursive
wildcards. The leaf `name` is always exact: `*` means multiplication. All identifiers use ASCII
case folding, and dots inside a component remain literal. `type` may be omitted/null or one of
`scalar`, `aggregate`, `table`, `macro`, `table_macro`, `window` (ASCII case-insensitive).
Omission covers all supported kinds at that identity; all overloads share a grant. Windowed
aggregates have kind `aggregate`; standalone window functions have kind `window`.

Both layers must authorize the resolved identity. Eligibility of a written leaf merely allows
resolution; it cannot grant a namespace. Never-bind and control-plane rules keep their origin
semantics. Blocks stay VARCHAR[] and deny alias-canonicalized leaves across namespaces.
Reviewed Parquet and JSON grant aliases apply only to their intended system table/scalar
identities, never to a host function or macro with an alias-like name.

Defaults cover reviewed `system.main` identities, including reviewed extension functions there.
They do not cover host shadows or PostgreSQL compatibility macros in `system.pg_catalog`.
The inventory's historical classifications and source reviews remain unchanged. Explicit host
macro grants continue to authorize opaque bodies, including forwarded arguments; caller code
sharing their names remains conservatively caller-attributed.

## Migration

0.3.0 shipped JSON v1. Migrate once to v2, changing both table schema fields and function grants.
Replace `"allowed_functions":["abs"]` with
`"allowed_functions":[{"catalog":"system","schema_path":["main"],"name":"abs"}]`.
There is no string-grant compatibility or mixed-list format. Empty lists still work. Canonical
settings have all four fields and are NULL-free: empty catalog/type mean unrestricted catalog/kind.
Read-modify-write the canonical setting rather than constructing a partial STRUCT that DuckDB
could cast lossily. JSON schema and typed decoding enforce the same shape.

## Feasibility matrix

Source basis: DuckDB 1.5.5 d8cdaa33f and 2.0 candidate d4e72566a. Neither engine pin is changed.

| Route | 1.5 provenance | 2.0 provenance | Enforcement and absent-provenance behavior |
| --- | --- | --- | --- |
| Catalog lookup | Full entry and stamped overloads | Full entry, nested path, QualifiedName | Private lookup callback checks actual identity/kind before function bind or macro expansion. |
| Bound scalar/aggregate/table | Stamps can be lost by specialization | Qualified implementation plus retained definition | Full identities checked; unknown caller identities refused. Narrow 1.5 recovery below. |
| Windows | Aggregates stamped; other windows are engine expression kinds | Catalog window entries and BoundWindowFunction | Aggregate identity checked; 1.5 intrinsic windows have explicit system identity; 2.0 actual window identity checked. |
| Implicit operators/constructors | Often unqualified calls | Still uses search path plus callback | Require system implementation even if host shadow is explicitly granted. Ambiguity can conservatively refuse mixed queries. |
| Direct builtin helpers / optimizer | System lookups or factory functions, often no callback | More system-qualified builtin helpers, still direct binding | Trusted engine transformations; current authorization is pre-optimizer, not a universal execution/callback interceptor. |
| Lambda bodies | ListLambdaBindData | Bind data and lambda nodes | Outer catalog identity checked; executable list body traversed explicitly. Nested direct routes retain their limits. |
| Caller collations | Embedded unstamped ScalarFunction, direct bind | Direct system scalar lookup; nested list_transform | 1.5 explicit caller COLLATE refused before private bind. 2.0 surviving functions checked by actual identity after bind. Host default/type collations remain trusted configuration. |
| Caller list aggregate dispatch | Direct system lookup; serialization may lose stamps | Direct system lookup and qualified serialization | Only unqualified calls with literal target names: authorize targets after resolving the actual system scalar dispatcher but before its callbacks. Dotted/method and computed-target calls refused; unrelated host same-leaf functions keep their own contracts. |
| Fixed list distinct/unique | Factory histogram | Factory histogram | Verified system dispatcher has source-backed histogram dependency, not discovered catalog selection. |
| Replacement reader | Returned function expression then catalog lookup | Same with qualified names | Leaf screened, actual entry authorized and returned reference pinned before reader bind. Unsupported replacement shapes refused. |
| Host macros | Full macro entry before expansion | Same, nested schemas | Macro authorized first, then existing body trust; control plane always denied. |
| Default macros | System entries, unqualified body helpers | Same | Fixed dependencies require system origin and obey blocks. Literal dispatch dependencies recorded from source body; not treated as arbitrary caller-selected grants. |

Relevant engine sites: `catalog_entry_retriever.cpp`, `bind_function_expression.cpp`,
`bind_operator_expression.cpp`, `bind_window_expression.cpp`, `collation_binding.cpp`,
`core_functions/scalar/list/list_aggregates.cpp`, `aggregate/distributive/minmax.cpp`.

### 1.5 specialization scope

Some reviewed binders (sum/avg/min/max/first/last/any_value/arbitrary/quantile/median/mode/entropy) replace a catalog
overload with a factory implementation, losing its namespace. Gatekeeper may retain a definition
identity only when this same private authorization recorded exactly one matching aggregate entry,
that entry is system.main, and no competing same-name namespace was observed. This is evidence of
the admitted definition under the trusted-engine model, not pointer-level proof of every specialized
callback. Other missing identities refuse; no live relookup, policy-leaf match, or plan-evidence
same-leaf merge supplies provenance. Mixed same-name definitions conservatively refuse recovery.

SELECT-list UNNEST and 1.5 intrinsic windows are source-defined engine operations with explicit
system identities. Fixed histogram is likewise an intrinsic dependency. These are not claims that
a catalog lookup selected those implementations. Arbitrary unknown functions never inherit them.
The 1.5 scalar-subquery planner creates count_star directly; recovery requires equality with the
builtin aggregate callbacks, not just that leaf. A statically linked loadable has its own engine
copy, so recognition accepts either its factory callbacks or the host's fixed, internal
`system.main.count_star` overload captured without binding. That fingerprint is not a grant or
caller dependency; normal policy still applies to every recognized intrinsic. Parser-implied aliases are canonicalized before
checking system origin. `contains` (IN-list) and `regexp_full_match` (SIMILAR TO), like literal
constructors, are conservatively system-only even when explicitly called: the parsed AST does not
reliably distinguish their syntactic origin. A host grant cannot redirect these helpers.

### Timing limits and unresolved engine hooks

The private binder's ordinary catalog callback is a real pre-bind authorization boundary.
It is **not** a universal zero-callback guarantee. Parameterized enforcement can bind in DuckDB
before private authorization; 1.5 Prepare binds before a usable statement hook. Execution rebinds
under current policy, preventing stale grants, but cannot undo earlier callbacks. Log-only records
the same refusal and intentionally lets the engine run. Raw PRAGMA preprocessing remains the
separately documented pre-hook residual; validate-first is the strongest text boundary.

Collation helpers and list dispatch bind directly without the callback. Literal dispatch prechecks
do not evaluate arguments to discover authorization; engine bind-time expression evaluation and
serializer callbacks remain trusted implementation work. Serialization is a late backstop, not the
pre-bind authorization mechanism. Collated min/max directly select arg_min/arg_max by search path:
Gatekeeper conservatively checks these dependencies before caller min/max binding and refuses
host shadows even when a grant would admit them. Trusted native callbacks can perform their own
lookups; function grants are not a sandbox for their implementation code.

A complete interception contract needs upstream hooks for engine-owned binders/preparation,
direct function binding, implementation replacement, nested dispatch, and optimizer binding,
with origin and immutable definition identities. A post-optimizer walk alone is still too late
for callback side effects. This implementation uses no engine fork or catalog callback mutation.
Known denied identities produce `forbidden` with identity-bearing function violations; unsupported
caller bind-time routes are refused before private binding. Engine failures remain `binding`.

## Validation targets

`gatekeeper_qualified_probe` (with `GATEKEEPER_NATIVE_PROBES=ON`) registers same-leaf native
table functions in different schemas and asserts that denied namespace/kind paths have zero bind
callbacks during private validation. `gatekeeper_prepared_probe` also withdraws a qualified macro
grant while retaining the same prepared handle. The compatibility workflow runs both.
Portable SQL tests, Python namespace/type/alias tests, source-only matcher/schema checks, and Wasm
EH smoke checks cover the policy cutover. Full native/loadable, browser and integration runs are
still required after building; header-only syntax checks do not establish runtime compatibility.

Validated stacked above #107 (59fb40b), preserving #106, with isolated `EXTENSION_STATIC_BUILD=OFF`
loadables and explicit artifact loading (no shared-build configuration changes):

- Full Python suite: 1.5 default parser **1576 passed, 43 skipped, 2 xfailed**; 1.5 PEG
  **1574 passed, 45 skipped, 2 xfailed**; 2.0 **1606 passed, 13 skipped, 2 xfailed**.
- Portable SQL: 1.5 **766 assertions / 14 cases** (two feature skips); 2.0 **804 assertions / 16 cases**.
- Native qualified-function/shifted-dispatch callback, prepared-policy/parameter-fallback, and
  remote-catalog probes pass against both shared engine libraries while loading the new artifact.
- Both loadables pass the positive and negative engine guard checks. External integration fixtures,
  browser, sanitizer and fuzz execution are not part of these runs.

Parameter fallback uses the same matcher at fixed `system.main.getvariable` / `scalar` identity:
host shadows, wrong kinds and wrong namespaces cannot grant that capability. #107's conservative
enforced collision policy and #106's local CONNECT guards are retained.

CI's statically linked loadables require an additional cross-library check: the host and extension
have separate engine callback addresses. Relinking against the read-only 1.5 engine archive reproduced
all four PR #113 count_star parity failures. After recognizing both engine-owned callback sets, that
artifact passed the full 1.5 Python suite (**1576 passed, 47 skipped, 2 xfailed**), the PEG qualified/
audit/enforcement/log-only modules (**411 passed, 5 skipped, 2 xfailed**), the native qualified probe,
and the engine guard. The affected 2.0 modules passed (**416 passed, 2 xfailed**). These checks use no
leaf-only intrinsic authorization and do not replace a sanitizer CI rerun.
