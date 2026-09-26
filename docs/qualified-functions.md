# Qualified function rules (policy v2)

`allowed_functions` and `blocked_functions` accept only STRUCT/object rules:

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
semantics. Blocks use the same namespace, exact-depth path, leaf and optional kind matcher as grants;
either layer's matching block wins. Reviewed Parquet and JSON aliases apply only to their intended system table/scalar
identities, never to a host function or macro with an alias-like name.

Defaults are explicit `{catalog, schema_path, name, type}` identities, including reviewed extension functions.
Every default has an exact kind; a host native table function registered in `system.main` under a
reviewed scalar name does not inherit that scalar's permission. No runtime kind discovery or any-kind
default is used. Generation embeds the reviewed inventory identities without inferring kinds.
They do not cover host shadows or PostgreSQL compatibility macros in `system.pg_catalog`.
The inventory's historical classifications and source reviews remain unchanged. Explicit host
macro grants continue to authorize opaque bodies, including forwarded arguments; caller code
sharing their names remains conservatively caller-attributed.

## Migration

0.3.0 shipped JSON v1. Migrate once to v2, changing table schema fields and both function rule lists.
Replace `"allowed_functions":["abs"]` with
`"allowed_functions":[{"catalog":"system","schema_path":["main"],"name":"abs"}]`.
Replace `"blocked_functions":["md5"]` with
`"blocked_functions":[{"catalog":"system","schema_path":["main"],"name":"md5","type":"scalar"}]`.
To deliberately cover all catalogs and all one-component schemas, use `catalog:"*", schema_path:["*"]`;
that rule does not cover deeper schema paths. There is no string-rule compatibility or mixed-list format.
Empty lists still work. Canonical
settings have all four fields and are NULL-free: empty catalog/type mean unrestricted catalog/kind.
Read-modify-write the canonical setting rather than constructing a partial STRUCT that DuckDB
could cast lossily. JSON schema and typed decoding enforce the same shape.

## Feasibility matrix

Source basis: DuckDB 1.5.5 d8cdaa33f and the inspected 2.0 candidate d4e72566a;
the repository's compatibility workflow also pins 2.0 candidate 6844d1b. Neither engine pin is changed.

| Route | 1.5 provenance | 2.0 provenance | Enforcement and absent-provenance behavior |
| --- | --- | --- | --- |
| Catalog lookup | Full entry and stamped overloads | Full entry, nested path, QualifiedName | Private lookup callback checks actual identity/kind before function bind or macro expansion. |
| Bound scalar/aggregate/table | Stamps can be lost by specialization | Qualified implementation plus retained definition | Full identities checked; unknown caller identities refused. Narrow 1.5 recovery below. |
| Windows | Aggregates stamped; other windows are engine expression kinds | Catalog window entries and BoundWindowFunction | Aggregate identity checked; 1.5 intrinsic windows have explicit system identity; 2.0 actual window identity checked. |
| Implicit operators/constructors | Often unqualified calls | Still uses search path plus callback | Require system implementation even if host shadow is explicitly granted. Ambiguity can conservatively refuse mixed queries. |
| Direct builtin helpers / optimizer | System lookups or factory functions, often no callback | More system-qualified builtin helpers, still direct binding | Trusted engine transformations; current authorization is pre-optimizer, not a universal execution/callback interceptor. |
| Lambda bodies | ListLambdaBindData | Bind data and lambda nodes | Outer catalog identity checked; executable list body traversed explicitly. Nested direct routes retain their limits. |
| Caller collations | Embedded unstamped ScalarFunction in system.main collation entry | Direct system scalar lookup; nested list_transform | 1.5 records exact embedded scalar names from the caller's system collation entries; absent stamps recover only those capabilities, without competing host scalar evidence. Surviving implementations pass qualified grants/blocks. Host default/type collations remain trusted configuration. |
| Caller list aggregate dispatch | Direct system lookup; serialization may lose stamps | Direct system lookup and qualified serialization | Only unqualified calls with literal target names: authorize targets after resolving the actual system scalar dispatcher but before its callbacks. Dotted/method and computed-target calls refused; unrelated host same-leaf functions keep their own contracts. |
| Fixed list distinct/unique | Factory histogram | Factory histogram | Verified system dispatcher has source-backed histogram dependency, not discovered catalog selection. |
| Replacement reader | Returned function expression then catalog lookup | Same with qualified names | Leaf screened, actual entry authorized and returned reference pinned before reader bind. Unsupported replacement shapes refused. |
| Host macros | Full macro entry before expansion | Same, nested schemas | Macro authorized first, then existing body trust; control plane always denied. |
| Default macros | System entries, unqualified body helpers | Same | Fixed dependencies require system origin and obey blocks. With defaults disabled, expansion functions and literal aggregate targets each require qualified grants in that layer. With defaults enabled, reviewed fixed dependencies remain part of the default capability. Host macro bodies remain opaque. |

Relevant engine sites: `catalog_entry_retriever.cpp`, `bind_function_expression.cpp`,
`bind_operator_expression.cpp`, `bind_window_expression.cpp`, `collation_binding.cpp`,
`core_functions/scalar/list/list_aggregates.cpp`, `aggregate/distributive/minmax.cpp`.

### 1.5 specialization scope

Engine aggregate binders can replace a catalog overload with a factory implementation, losing its
namespace. Gatekeeper may retain an aggregate definition
identity only when this same private authorization recorded exactly one matching aggregate entry,
that entry is system.main, and no competing same-name namespace was observed. This is evidence of
the admitted definition under the trusted-engine model, not pointer-level proof of every specialized
callback. Other missing identities refuse; no live relookup, policy-leaf match, or plan-evidence
same-leaf merge supplies provenance. Mixed same-name definitions conservatively refuse recovery.

SELECT-list UNNEST and 1.5 intrinsic windows are source-defined engine operations with explicit
system identities. Fixed histogram is likewise an intrinsic dependency. These are not claims that
a catalog lookup selected those implementations. Arbitrary unknown functions never inherit them.
The 1.5 scalar-subquery planner creates count_star directly. When attributable to a caller's count,
the same observed-definition rule applies; a helper with no caller origin remains an engine
dependency and may retain unknown namespace in evidence. There are no callback-pointer fingerprints,
per-name specialization lists, or stored engine objects. Parser-implied aliases are canonicalized before
checking system origin. `contains` (IN-list) and `regexp_full_match` (SIMILAR TO), like literal
constructors, are conservatively system-only even when explicitly called: the parsed AST does not
reliably distinguish their syntactic origin. A host grant cannot redirect these helpers.

For 1.5 COLLATE, `PushVarcharCollation` resolves each dot-separated collation component exclusively
in `system.main` and binds the entry's embedded scalar. Gatekeeper reads those exact entries before
private binding (without invoking scalar callbacks), records their implementation names, and uses
that source-backed capability identity only for unstamped matching bound scalars. It does not turn
every `lower` or `icu_collate_*` into a builtin. Explicit scalar shadows are catalog-authorized first;
a competing host scalar observed in the bind prevents unstamped collation recovery. Native collation
registration and implementation code remain host-trusted. Exact entry-name recording also attributes
renamed 2.0 ICU scalars, without assuming a prefix. New names require explicit grants until reviewed
into defaults. Grant checks still apply after binding,
so this is not a pre-callback interception guarantee for collation code.

### Timing limits and unresolved engine hooks

The private binder's ordinary catalog callback is a real pre-bind authorization boundary.
Before resolution, a leaf can be refused only when no eligible identity survives: defaults retain
their exact kinds and explicit grants retain their namespace/kind patterns. A blanket block covering
all eligible identities therefore preserves early refusal, including before unrelated bind callbacks.
A scoped block that leaves another eligible namespace or kind must wait for the actual catalog entry;
the lookup callback then checks it before the selected implementation's bind callback or macro expansion.
Blocks never authorize an identity and cannot supply missing caller provenance.
It is **not** a universal zero-callback guarantee. Parameterized enforcement can bind in DuckDB
before private authorization; 1.5 Prepare binds before a usable statement hook. Execution rebinds
under current policy, preventing stale grants, but cannot undo earlier callbacks. Log-only records
the same refusal and intentionally lets the engine run. Raw PRAGMA preprocessing remains the
separately documented pre-hook residual; validate-first is the strongest text boundary.

Collation helpers and list dispatch bind directly without the callback. Literal dispatch prechecks
do not evaluate arguments to discover authorization; engine bind-time expression evaluation and
serializer callbacks remain trusted implementation work. Serialization is a late backstop, not the
pre-bind authorization mechanism. Collated min/max directly select arg_min/arg_max by search path:
Gatekeeper conservatively checks these dependencies before caller system.main min/max binding and refuses
host shadows even when a grant would admit them. An explicitly granted host min/max aggregate has
its own implementation and is not subject to this system-only helper check. Default-macro aggregate
targets retain the check because their selection is fixed to system.main. Trusted native callbacks can perform their own
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

Parameter fallback uses the same matcher at fixed `system.main.getvariable` / `scalar` identity:
host shadows, wrong kinds and wrong namespaces cannot grant that capability. Granted collisions
retain DuckDB's explicit-value precedence and conservatively report fallback capability evidence;
ungranted collisions refuse. CONNECT routing stays refused even in log-only mode.
