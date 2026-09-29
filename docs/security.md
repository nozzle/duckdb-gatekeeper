# Security model

For Quack, see the [remote authorization support matrix](quack.md): evidence is host-only checked
local binding scope, caller-written delegation is never-bind, and server-created connections are
not automatically enforced. Opaque trusted definitions are unsupported: deferred binding can
execute remotely before a later refusal. The matrix also identifies the native 1.5 preparation limit.

Gatekeeper decides whether one SQL statement conforms to the selected syntax, caller-function
and resolved-deny/object policies on the build engine's parser and binder. It offers that decision two ways:
`gatekeeper_validate` returns it to the host before the host executes, and an
[enforced connection](#enforced-connections) makes DuckDB refuse to execute anything the
decision denies. Neither means the SQL is cheap, returns nonsensitive data, or cannot have side
effects through admitted functions. Gatekeeper is a statement-level sandbox, not an
operating-system, memory, or network sandbox.

## Integrating

Preferred: hand untrusted callers an enforced connection and execute their SQL on it directly.
The ordered setup (extensions and catalogs first, then the policy, the posture settings, the
log, `lock_configuration`, and `CALL gatekeeper_enforce()` on every connection handed out) is
the [trusted setup table](../README.md#enforced-connections) in the README; what each step
protects is in [enforcement semantics](#enforcement-semantics), [log-only mode](#log-only-mode),
and the [audit log](#audit-log) below. Two points are easy to get wrong:

- Gatekeeper never changes host settings. `autoload_known_extensions`,
  `autoinstall_known_extensions`, `enable_external_access`, and `lock_configuration` are the
  host's; `CALL gatekeeper_enforce()` reports the ones that weaken the sandbox in `warnings`,
  along with [log-only mode](#log-only-mode) being on and logging that would not
  [record a denial](#audit-log).
- Enforced connections cannot read the in-memory log (`duckdb_logs` is never-bind); the host's own
  unenforced connections can, or `storage := 'file'` or `'stdout'` puts the trail outside the
  process altogether.

Validate-first, for hosts that cannot dedicate a connection:

1. The same setup through the policy and `lock_configuration`. Construct any further request
   restrictions from authenticated context.
2. Run `SELECT * FROM gatekeeper_validate(?)` with the exact SQL to execute.
3. Require an explicit successful result; reject missing results, NULLs, and exceptions.
4. Execute the same SQL on the same connection under controlled database/process settings.
   The application must require validation and control access to the raw connection.

`CALL gatekeeper_configure` atomically replaces a database-scoped authorization ceiling.
Request overrides can only narrow it: both policy layers must authorize the query,
and either layer's blocks win. Only trusted bootstrap should configure the instance.
After setup, `SET lock_configuration=true` blocks configuration through `CALL`, `SET`,
and `RESET`, unless the host deliberately exempts `gatekeeper_policy` in `allowed_configs`.
This protects Gatekeeper's policy, not arbitrary SQL execution: on unenforced connections the
application must still require validation and control access to the raw connection/native APIs.
Configuration is nontransactional; a surrounding rollback does not undo replacement.
Each validation call takes one coherent snapshot at execution. Lock before exposing the instance.
Use strict parameterized `CALL` for authoring; direct STRUCT `SET` silently drops
unknown extra keys at any depth during DuckDB casting. The canonical setting is
NULL-free, so a typo that displaces a canonical field (a missing or NULL-filled nested
`catalog`, `schema_path`, or leaf) fails closed instead of widening catalog matching.
See [global policy](../README.md#global-policy) in the README.

Validation returns one row with `allowed`, `code`, `violations`, `error_type`,
`error_message`, `position`, `objects`, `functions`, `caller_objects`, and `caller_functions` as named columns. Require
`allowed = true` and `code = 'ok'`. The diagnostic/dependency lists retain nested
STRUCT elements. SQL text and options accept constant expressions or host-bound
parameters, not correlated/lateral per-row expressions. For multiple SQL strings,
make separate parameterized calls. Prepared executions read the current policy and
bind the submitted SQL again; preparing a call does not cache an authorization decision.
Validation also rejects non-null placeholder plans with unresolved parameter types;
otherwise execution could rebind to an implementation the validator never authorized.

Native scalar/aggregate substitutions use retained definition provenance on DuckDB 2.0:
the original definition's qualified identity determines caller origin even if its bind
callback changes the surviving implementation's name or namespace. That implementation
must satisfy caller policy too. Identity comparisons do not rely on callback pointers
across the host/loadable engine boundary. Engine-generated casts do not inherit origin
from unrelated caller functions, and exact trusted-body-only identities remain trusted.

DuckDB 1.5 does not retain the original definition after a native bind callback replaces
its descriptor. Gatekeeper therefore refuses caller-attributable non-system scalar entries
with bind, extended-bind, or expression-bind callbacks, and non-system
aggregate entries with bind callbacks, before invoking them. The check covers every
overload because the catalog hook precedes overload selection. On both engines, caller
non-system scalar expression-bind callbacks are refused because they can replace the
entire expression and discard descriptor provenance. These refusals report `forbidden`
with the `unsupported_structure` rule; explicit grants cannot supply missing provenance.
Ordinary native functions without these
callbacks and callbacks reached only inside trusted definitions remain usable.
Lambda-type callbacks alone are not refused: they return a `LogicalType` and do not
receive a mutable function descriptor. Executable lambda bodies have separate traversal checks.

This is a surviving-plan authorization boundary, not a sandbox for native extension code:
native code and the engine are trusted to preserve their provenance metadata. It does not
undo effects of a callback that runs before the plan check, and malicious native code can
forge metadata or execute outside a returned expression. The existing native-prepare and
other early bind-time timing limits still apply.

On DuckDB 2.0, caller-written `$name` references with a same-named session variable require the
fixed `system.main.getvariable` capability before validation binds anything. Both policy layers
must allow it; blocks win. Successful validation includes `{catalog: 'system', schema_path: ['main'],
name: 'getvariable', type: 'scalar'}` in `functions`, without variable values. A present NULL variable
is still a fallback input. Positional `$1` never falls back. References introduced only by trusted
views remain the definition's own, outside caller policy.

Enforcement is conservative: **caller named-parameter/session-variable collisions require
`getvariable` permission before binding, even with explicit arguments**. QueryBegin
cannot see arguments; the 2.0 prepared-rebind hook sees arguments after implicit defaults were merged.
When granted, both possible sources are authorized: DuckDB preserves explicit-value precedence and
the decision conservatively includes the capability even when no fallback was actually read.
Preparing colliding text also requires the grant because the early hook cannot distinguish that
operation. Retained handles are checked at QueryBegin on every execution. Noncolliding explicit
inputs and DuckDB 1.5 retain their existing behavior. Log-only records one denial per statement and
lets the engine proceed. A colliding explicit input without the grant remains conservatively refused.
See [the feasibility decision](parameter-fallback.md) for the missing hook and deferred value-input API.

Capability evidence contains only the fixed identity, never variable values. Raw validation/audit
diagnostics are host-facing and retain the engine's messages, which can include values in regex,
path or cast errors. Enforcement engine errors likewise propagate unchanged; this is not a
diagnostic-redaction boundary.

Grant direct SQL access to `system.main.gatekeeper_validate` (kind `table`) only when the
caller is entitled to its full host-facing result, including raw diagnostics and trusted
dependencies. A caller holding that grant can select every result column; asking it to select
only `allowed` is not a disclosure boundary. Otherwise, keep validation host-mediated and
return only an approved projection, with generic errors where needed.

Use `SELECT allowed FROM gatekeeper_validate(...)` to select an individual column,
or select `*` for all result columns.
Untyped empty option lists (`[]`) are accepted despite DuckDB resolving them to `INTEGER[]`.
Empty or all-NULL lists otherwise bypass the element-type check, except legacy function
`VARCHAR[]`, which is rejected even when empty. `[NULL]` and `[NULL]::DOUBLE[]` return
`invalid_input` at execution. Lists with non-NULL members require the documented element types.
Nested identity fields are preserved and checked, including the field names of typed empty
STRUCT lists. Legacy function strings and the old `schema` field receive consistent guidance
to the v2 rule shape; follow the [policy v2 migration guide](policy-migration.md).

### Table ACL matching

Tables and views are unrestricted until a layer configures `allowed_tables`; only internal
objects (those with `CatalogEntry::internal = true`) need an explicit rule from the start. Set
`allowed_tables` in the global policy during trusted setup when tenants must not see every
table; `[]` denies all tables and views. The rules, which the README's
[table ACL](../README.md#table-acl) section illustrates:

- A rule names a `catalog`, `schema_path`, and `table`; all three are matched against the
  **resolved** identity of a table or view, never the caller's spelling, a CTE name, a file
  path, or a reader argument. Text is exact and ASCII case-folded. The nonempty schema path
  contains literal identifier components, outermost first, and matches at exactly its depth.
  A dot inside a component is part of that identifier, never a path separator.
- Rules apply to the objects attributable to the caller: those the caller's own text names,
  wherever the name binds, and those the caller's own binders retrieve. A trusted definition
  (a host view, scalar or table macro, or an attached catalog's table or view) is
  authorized by its own identity, and what its body reads is its own, outside every rule
  below: allowing a view admits the tables behind it, and a CTE, alias, or table the caller
  reads under a name a definition also reads makes that object the caller's, query-wide
  (conservative; rename the CTE to lift it). The evidence still lists everything read. See
  [trusted definitions](#function-enforcement-and-trusted-expansion) for the mechanism.
- Only a whole-component `*` is a wildcard (`sales_*`, `?`, and `%` are literal names). A
  wildcard also matches objects created or attached later, and `catalog: '*'` matches
  temporary shadow tables. An omitted `catalog` is `*`. Each `'*'` in `schema_path` matches
  one component: `['finance', '*']` matches an immediate child, not a descendant of that child.
  There is no recursive wildcard; `'**'` is literal. `['*']` matches only top-level schemas.
- Within a layer `allowed_tables` is a union: any matching rule grants. Between layers it is an
  intersection: both the ceiling and the request layer must grant. Multiple entries pair
  specific catalogs and schemas without granting their cross-product.
- `blocked_tables` uses the same matching, defaults to none, and works independently of the
  allowlist. A matching block in either layer always wins for what the caller names; it does
  not reach the tables and views a trusted view or macro reads. Block the view or macro to
  withdraw it.
- Internal objects the caller names need an allow rule with every schema component and the
  table name exact in each layer; schema/table wildcards never grant them, though the catalog
  may be `*`, NULL, or omitted. The actual entry's `internal` flag controls this, not its
  catalog or a name prefix. Block wildcards do match them, even when an exact allow rule exists. Metadata
  *readers* stay on the [never-bind list](#never-bind-functions) for the caller's own text
  regardless, so an exact rule for a caller-named metadata view is necessary and not
  sufficient; a host view or macro over an internal view is the host's decision to expose
  it, reader included.
- Schema-wide `SHOW` is denied whenever either layer configures any table restriction;
  `DESCRIBE table` checks the resolved table normally.
- Table rules govern tables and views only. Types, casts, and collations are trusted as part of
  the host-configured database and need no permission by name; function policy still applies
  to the implementations they bind (`'a' COLLATE nocase = 'A'` binds `lower`), see
  [callback bypasses](#callback-bypasses).

Resolved object denials report `catalog`, `schema_path`, `table`, and `object_type`
(`table` or `view`) in `violations`, including allowlist misses, blocks, and internal-object
refusals. The `table` rule names the policy check, not the object's kind. These denied
identities remain available when the success-only evidence lists are empty, including in
the [audit log](#audit-log).

### Declared input validation

For a SQL node with declared inputs, pass only those inputs as `allowed_tables`, without
adding their ancestors. Validate on the real connection after prerequisite relations exist.
On success, `caller_objects` reports the catalog tables/views attributable to the caller;
`objects` also reports dependencies introduced by trusted definitions. For B, a view over C:

| Query | Allowed tables | `caller_objects` | `objects` | Decision |
| --- | --- | --- | --- | --- |
| `SELECT * FROM B` | B | B | B, C | allowed |
| `SELECT * FROM B JOIN C USING (id)` | B | empty | empty | forbidden |
| `SELECT * FROM B JOIN C USING (id)` | B, C | B, C | B, C | allowed |

The same applies to a host source view over an attached Iceberg or DuckLake relation: declare
the source view, not its backing table. Binding still resolves and may perform I/O through the
lakehouse. Nested views remain opaque; a separately referenced inner view becomes caller-attributable.

For example, after creating `reporting.source_b` over `lake.main.orders` on the connection:

```python
declared = {("memory", ("reporting",), "source_b")}
rules = [{"catalog": c, "schema_path": list(s), "table": t} for c, s, t in declared]
row = con.execute("""
    SELECT allowed, code, caller_objects
    FROM gatekeeper_validate(?, allowed_tables := ?)
""", [sql, rules]).fetchone()
if row is None or not row[0] or row[1] != "ok":
    raise ValueError("Query does not satisfy its declared inputs")
# Fold ASCII only, like DuckDB identifiers and Gatekeeper's rules, not Unicode casefold().
fold = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
actual = {(o["catalog"].translate(fold), tuple(s.translate(fold) for s in o["schema_path"]),
           o["table"].translate(fold)) for o in row[2]}
expected = {(c.translate(fold), tuple(part.translate(fold) for part in s), t.translate(fold))
            for c, s, t in declared}
if actual != expected:
    raise ValueError("Declared inputs differ from caller-attributable inputs")
```

Let validation exceptions propagate as failures. The global ceiling must also allow the
declared objects. A successful decision already establishes the allowed-input subset;
the equality comparison additionally detects unused declarations. Select named columns:
`caller_objects` is column nine and `caller_functions` appends column ten. Both are included
in audit decisions, where the latter shifts subsequent metadata positions; see the
[migration note](policy-migration.md#caller-function-evidence-in-040). Existing refusal ordering is unchanged.

`functions` remains combined host-facing evidence, including caller-attributable functions
and trusted dependencies. `caller_functions` is the subset checked by caller-scoped function
policy at any authorization point; `caller_objects` is the conservative catalog-table/view subset.

For declared function capabilities, require successful validation and check permitted-set
inclusion: every non-default `caller_functions` identity must be covered by a declared function
rule. Do not require equality: declarations may be unused and defaults contribute identities.
Determine default coverage from the reviewed qualified default identities, not a name-only list;
actual internal-origin checks remain Gatekeeper's responsibility. Prefer passing the declared
grants as policy so Gatekeeper enforces them directly. Evidence is not a policy replacement.
See [function evidence scope](qualified-functions.md#caller-function-evidence) for preflight-only
names, implied capabilities, and engine-specific conservative attribution.

On a function-policy denial, `violations` identifies the offending function (possibly only its
preflight name); `caller_functions` and all other evidence lists are empty, including log-only
denials. Hosts cannot mine denied audit evidence for a complete grant set.

**Evidence contract:**

- Entries have the same `{catalog, schema_path, table, type}` shape as `objects`, with `type`
  `table` or `view`. They preserve resolved catalog spelling, are sorted and deduplicated
  by those four fields, and form a subset of `objects`. Compare identities as structured
  components, ASCII case-insensitively; dots within quoted names are not separators.
- Caller attribution wins when an identity is reached both directly and through a trusted
  definition. CTE aliases are not catalog entries; tables read by consumed CTEs are. Unused
  CTE bodies may never bind. Temporary shadows and attached catalogs retain their resolved identities.
- This is **conservative policy attribution**, not exact lexical dependency extraction.
  A caller-written name can also attribute a matching object inside a trusted definition,
  even when that name resolves to a CTE or a different schema for the caller. Even an unused
  CTE's written table name participates if that object is retrieved elsewhere. Alias
  declarations alone do not. Rename colliding CTE references or use unambiguous qualification
  when a consumer needs a narrower set.
- Macros are function capabilities, not entries in `caller_objects`; their hidden tables
  remain in `objects`. Replacement scans likewise appear as `type = 'replacement'` only
  in `objects`, and reader functions appear in `functions`. An empty `caller_objects` does
  **not** mean no data access. Table-input-only consumers must control macro/reader grants
  in the global policy and expose external inputs through host-created catalog views.
- Every failed decision returns an empty list, including failures after some objects were
  resolved. A successful empty list means no caller-attributable catalog objects were retrieved.
  No diagnostic collection mode or continued binding after denial is introduced.

### Secure views and host-only evidence

On DuckDB 2.0, a host-created `CREATE SECURE VIEW` is authorized by the existing
`catalog`/`schema_path`/`table` rules and reported as `type = 'view'`. Its body binds in
the same trusted child scope as an ordinary host view, including nested regular/secure
views and hidden readers. A caller's separate reference to an object or function still
receives caller policy; query-wide name collisions have the conservative behavior above.
Resolved ACL denials identify the secure view with `object_type = 'view'` in validation
and audit violations. A denied backing table is `object_type = 'table'`; unresolved or
non-object violations leave the kind empty rather than inferring it from SQL text.
An internal function written by the caller still needs an exact-schema grant: schema
wildcards do not grant internal functions, while wildcard blocks continue to apply.

Gatekeeper admits `LogicalSecureView` as a read-only wrapper and traverses its child for
authorization, transitive binding evidence, and private-bind/executed-plan scan accounting.
It does not remove or rewrite the wrapper. Both checks run before optimization: caller
predicates are checked while still caller-attributable, even when DuckDB later pushes them
beneath the boundary. DuckDB retains control of its predicate, plan-display, and statistics
barriers; admitting a secure view does not disable them.

**Validation results and audit diagnostics are privileged host information.** This includes
`objects`, `functions`, `caller_objects`, `caller_functions`, violation messages, and engine errors. Secure views
do not redact these lists: host evidence retains transitive dependencies under the same
binding-evidence limits as ordinary views. There is no new identity kind, redaction field,
or claim of completeness after redaction.

`caller_objects` is not a confidentiality-safe public projection or an exact lexical
dependency list. It can include a hidden object retrieved inside a trusted body when a
caller-written name also matches it, even if that name resolves to a CTE in the caller's
scope. A refusal can also name that hidden object in `violations`. The tested 2.0 engine
does not sanitize missing-dependency binding errors inside secure views: dropping a backing
table can reveal its name in the engine error. Gatekeeper preserves the engine diagnostic,
including in log-only mode; failed decisions have empty `objects`, `functions`, `caller_objects`,
and `caller_functions` lists.

Applications may deliberately expose a minimal decision or a separately reviewed projection
and should mediate execution errors as well as validation output if names must stay hidden.
A confidentiality-safe public diagnostics interface is a separate design, not a guarantee
of `SECURE VIEW` support or of `caller_objects`.

## Enforced connections

### Threat model

The caller can submit arbitrary SQL text to an enforced connection and observe results and
error messages. The host process, its code, the objects it created (views, macros, attached
catalogs), and the connections it did not enforce are trusted. Host-language APIs on the
connection object itself (Python's `DuckDBPyConnection` methods other than executing SQL,
the C++ `Connection`) are out of scope: a caller holding them can open a new, unenforced
connection. Hand out the ability to execute SQL, not the object.

### CONNECT mode and native host state

**Local enforcement requires a LOCAL connection throughout its use.** DuckDB 2.0's
`ClientContext::SubmitStatement` checks `IsConnected()` and calls
`Catalog::RemoteExecute(context, original_sql)` **before** `BeginQueryInternal` and Gatekeeper's
`QueryBegin`. The returned table reference replaces the statement. Whether that callback
transmits or executes SQL immediately belongs to the catalog implementation; Gatekeeper
cannot authorize text before that callback on an already-connected session.

The supported host setup is to create a fresh local connection (or explicitly `DISCONNECT`
during trusted setup), end any host transaction, and execute `CALL gatekeeper_enforce()`
locally before accepting untrusted SQL. Keep it local afterward. Attaching a catalog is
different from entering CONNECT mode; local queries over attached tables continue to use the
normal authorization path. CONNECT-mode local enforcement and automatic enforcement of
connections created by a remote server are unsupported. Loading Gatekeeper on a client does
not latch the server's sessions: a server must perform its own trusted setup on each local
connection that executes untrusted SQL.

The boundaries, verified by `test/native/remote_catalog_probe.cpp` with a counted
`DuckCatalog` subclass implementing `RemoteExecute(string)`, are below. The dispatch/latch
trace originally covered 2.0 snapshot `6844d1bd8b` and the wheel-matched `d4e72566aa`
(`v2.0.0-alpha42986`); their relevant client-context and attachment implementations agree.
The native probe also passed the 0.4.1 CI snapshot `d591bb1da2`.
The subsequent `8b3c3b7dbf` snapshot adds connected parser grammars: parameterless
prepared execution and preparation on native-mutated connected sessions can now receive
a Gatekeeper text refusal after remote dispatch, rather than success or a missing-handle
error. The callback still runs first; these routes remain unsupported. The probe parses
its mock server response with local parser options, independently of the connected client.

| Route | Boundary and result |
| --- | --- |
| `CONNECT name`, connection-string CONNECT, or CONNECT in a batch on a local enforced connection | The existing non-SELECT text check refuses before binding/execution can change state or attach a target. Zero remote callbacks. `DISCONNECT` is also non-SELECT and refused. |
| Client `Prepare("CONNECT ...")` after latching, or execution of a CONNECT handle prepared before latching | Refused at the local text boundary; zero remote callbacks. SQL `PREPARE ... AS CONNECT` is rejected by the engine parser. Normal local parameterized SELECT handles remain supported. |
| A host macro selecting `gatekeeper_enforce()`, directly or via `query('SELECT ...')` | Control-plane catalog authorization refuses even inside trusted definitions. A macro does not grant SQL the right to change enforcement state. `query()` itself accepts only a single SELECT, not CONNECT. |
| Local activation body reached while `IsConnected()` is true | The latch throws a Permission Error and installs no enforcement state, even in log-only mode. It tests the flag, not just the live target, so stale/expired targets are refused too. |
| SQL activation submitted on an already-connected live session | Its original text reaches `RemoteExecute` first. It may never execute the local latch at all; a successful result is not evidence of local enforcement. Even if the returned plan invokes the local latch, its refusal is too late to protect that callback. |
| SQL activation with an expired/detached routing target | The engine refuses before Gatekeeper runs; `IsConnected()` remains true until explicit DISCONNECT. A detached target still held alive by trusted native code can remain routable. Neither detachment nor the absence of a usable target establishes LOCAL state. |
| Trusted native code calls `ConnectToCatalog` after latching | Subsequent SQL and parameterless prepared executions can reach the callback before a later Gatekeeper refusal. In the tested engine, client Prepare also dispatches before failing to register a local handle; bound-parameter execution is rejected by the engine before dispatch. None is a supported way to enforce remote execution. |
| CONNECT/DISCONNECT while log-only is on | Routing controls are identified by parsed statement type before log-only can waive a denial. They retain `mode = 'enforce'` and are refused before binding, with zero remote callbacks on local sessions. Turning log-only off therefore restores policy refusals on the same local route. Native-mutated connected state remains unsupported and must be restored through trusted native setup or the connection replaced. |

Host/native extension callbacks, UDFs, replacement scans, casts, and catalog implementations
are trusted code. Do not install or expose implementations that change an enforced
connection's routing state, including through an otherwise admitted view or macro. SQL
control-plane name checks cannot constrain an arbitrary native implementation calling
`ConnectToCatalog`, executing SQL on a fresh connection, or changing registered hook state.
The host must also keep state stable between prepare and execute. Public client entry points
that reach `SubmitStatement` share its early dispatch ordering; host APIs are not a separate
pre-callback authorization boundary.

Supporting already-connected enforcement requires an upstream veto/authorization hook
**before any remote dispatch**, covering direct submissions and prepared/client entry points,
plus a guard on connection-state transitions (including native `ConnectToCatalog`). A
`QueryBegin` connected-state check cannot supply either guarantee. These restrictions are
separate from the pre-hook PRAGMA-processing limitation in [#46](https://github.com/nozzle/duckdb-gatekeeper/issues/46).
DuckDB 1.5 has no CONNECT routing API; its local enforcement behavior is unchanged.

### Two boundaries

Gatekeeper decides at two points in DuckDB's local query lifecycle, subject to the LOCAL-state
host requirements above. Each owns a guarantee that can be stated and tested independently.

**Binding boundary** (`ClientContextState::QueryBegin`, before the engine binds). The
statement text is parsed with the connection's parser options, serialized, and walked
against the compiled grammar and the global policy exactly as `gatekeeper_validate` does.
When the statement has no parameters, it is then bound privately with the catalog-lookup
callback and replacement-scan interception, so every retrieved table and view is recorded by
resolved identity and by who retrieved it, and those attributable to the caller are
authorized; what a trusted view or macro body retrieves is that definition's own. Guarantee:
no SQL text submitted for execution reaches the engine's binder unless it is a single
`SELECT` whose grammar, caller-written functions and (parameter-free) caller-attributable
resolved objects the policy allows, or
the one statement DuckDB's own parser derives from such a `SELECT`: the temporary enum type of
a dynamic `PIVOT` (below), admitted by exact shape and checked as the `SELECT` that defines it.
Consequently an agent-written `read_csv('s3://...')`, `FROM 'file'`, or `duckdb_settings()`
never opens a file, socket, or metadata reader, and DDL/DML/`SET`/`LOAD`/`ATTACH`/`COPY`
never reach the binder.

**Execution boundary** (`PlannerExtension::post_bind_function`, after the engine binds and
before it optimizes or executes). The plan the engine produced must contain only reviewed
read-only logical operators, modify no database, return a query result, scan only the
sources the private bind of the admitted statement scanned, none of them more often than
that bind did (each `LOGICAL_GET` is matched by count: a table entry by resolved identity,
a table function by name; the tables attributable to the caller are authorized again), and
pass the same resolved-function
and implementation checks `gatekeeper_validate` applies to its own plan. The one other root
it accepts is a dynamic `PIVOT`'s enum type (`LOGICAL_CREATE_TYPE` of that exact shape, in the
temporary catalog, returning nothing) over such a plan. If the binding boundary deferred
object authorization because the statement had parameters, it runs here with the values the
engine bound them to. Guarantee: no plan executes on an enforced connection unless it consists
of allowlisted operators over the base tables the validated statement reached, each
authorized according to who reached it there, and allowed functions. This holds for every
plan the engine's planner produces, whatever produced the statement: SQL text, a prepared
statement, or DuckDB's relation API. Views are inlined before this point; who reached each
table is what the private bind's catalog callback recorded, which for a relation statement
sees the relation's SQL rendering rather than its query node. A node that scans a table or
table function the rendering never reached, or one more often than the rendering did, is
refused as a `statement` violation. A node that scans an identity exactly as often as a trusted
definition in the rendering did is not distinguished from it and runs under that definition's
authority; this is the same exposure function attribution has always had, and the linked fuzz
harness pins both halves (`CheckHostileRelation`).

Both boundaries read one policy snapshot per statement. A `Prepare()` only pre-screens the
prepared plan's structure: its parameter values are not known, and on DuckDB 1.5, which binds
it before any extension hook runs, no text is on record either, so nothing in it can be
attributed; table policy and function blocks alike wait for execution, where the rebind hook
(`OnExecutePrepared` on 1.5, `OnRebindPreparedStatement` on 2.0, whose `Prepare()` and
`Execute()` run as statements carrying the prepared text) forces a rebind inside the query so
the plan that runs is authorized under the current policy (the `authorize` boundary), and a
cached plan can never outlive a policy change. (On 2.0 the text boundary applies to the
prepare as well, so parameterless prepared text the policy denies is refused at `Prepare()`;
see [Compatibility and review](#compatibility-and-review).) Together the two boundaries make enforcement agree with `gatekeeper_validate` on every
statement that reaches them, which `test/test_enforcement.py` checks over a corpus of allowed,
denied, and erroneous statements. What DuckDB does to a statement before they run is listed
under residuals.

### Residuals

- **PRAGMA preprocessing runs before any hook.** DuckDB's statement preprocessor rewrites
  `PRAGMA` statements while parsing, inside `ClientContext::ParseStatements`, and to do so
  it binds and **evaluates every argument expression** (`Binder::BindPragma`,
  `ExpressionExecutor::EvaluateScalar`) before the pragma is even looked up and before any
  extension hook runs. On an enforced connection `PRAGMA anything(nextval('s'))` therefore
  advances the sequence, and `PRAGMA anything(error(current_setting('x')::VARCHAR))`
  reveals a setting through the error text (any failing cast leaks the value the same way),
  even though the statement is then denied. This happens for every statement in a batch
  before the first one executes, for every DuckDB connection, and from a plain
  `extract_statements` call (upstream:
  [duckdb/duckdb#25875](https://github.com/duckdb/duckdb/issues/25875)).

  What it reaches: **every scalar function visible to the connection**, with any arguments
  computable without table references (literals, casts, nested calls, lambdas), during the
  preprocessing of each statement and as many times as the argument expression invokes it
  (a list lambda over `range(n)` calls it `n` times), so the function allowlist does not
  apply on this path. That includes core functions, extension functions, host-registered
  UDFs, and scalar macros. What it cannot reach: table data (the binder rejects subqueries
  and column references, including inside macros), table functions, and any statement (DDL,
  DML, `COPY`, `ATTACH`, `LOAD`, `SET`). Core scalars that touch state include `nextval`
  (writes), `write_log` (when the host enabled logging: it writes any message under any log
  type, so `PRAGMA x(write_log('...', log_type := 'Gatekeeper'))` plants an entry in the
  [audit log](#audit-log) that either forges a decision or cannot be cast by
  `duckdb_logs_parsed`; a well-formed forgery is not distinguishable from a real record by
  content, and validate-first hosts are not exposed), `setseed` (own connection),
  and readers such as `current_setting`, `which_secret`, `getvariable`, `current_schemas`,
  `txid_current`; the inventory's `elevated` group is the full list of core names that read
  catalog, session, configuration, or planner state. What that is worth depends on the host:
  credentials kept in legacy `SET s3_*` options are readable once `httpfs` is loaded, a UDF or
  extension scalar that reaches the network or runs code is callable, and with
  `autoload_known_extensions` or `autoinstall_known_extensions` on, an unknown function name
  in a pragma argument triggers extension autoload through `Catalog::GetEntry`. The same
  preprocessor also runs query-pragma functions with their constant arguments: `PRAGMA
  import_database('dir')` reads `schema.sql` and `load.sql` before any hook, gated only by
  `enable_external_access` and `allowed_directories`.

  There is no interception point in front of it in DuckDB 1.5.6: `TransactionBegin` fires
  identically for `Prepare()` and carries no statement, a read-only transaction does not stop
  `nextval`, and the parser only yields to extensions through `allow_parser_override_extension`,
  which is host-gated, process-wide, and answered by whichever override loaded first (a
  Gatekeeper override was prototyped and declined for those reasons; see
  [#46](https://github.com/nozzle/duckdb-gatekeeper/issues/46)). `gatekeeper_validate`
  parses with `Parser` directly and never triggers it, so **hosts that cannot tolerate this
  residual should validate first**: pass the complete original text to `gatekeeper_validate`
  before any `execute` or `extract_statements` call, and execute only when it returns
  `allowed = true` and `code = 'ok'`, treating every other code, an exception, or a missing
  row as a denial. Do not key on `code = 'unsupported'` alone: a lone raw `PRAGMA` reports
  `unsupported`, but a batch such as `SELECT 1; PRAGMA anything(nextval('s'))` is refused as
  `forbidden` on statement count first, and text over the validator's size limit is refused
  as `forbidden` before it is parsed, while executing either still runs the pragma
  preprocessing. Unparseable text is refused as `parser` and fails in the engine's parser
  before any preprocessing, so it has no side effects, but the contract is the same: anything
  other than `ok` is a denial. Hosts that cannot interpose on the text must reject `PRAGMA`
  before it reaches any DuckDB parsing entry point. Keep credentials in the secret manager,
  autoload off, and side-effecting scalar UDFs or extensions off the shared instance; treat
  sequences the connection can see as writable by it. `test/test_enforcement.py` pins the
  gap with a strict `xfail` so an engine change is noticed.
- **A denial leaves the autocommit transaction open until the next query entry point.**
  DuckDB starts the transaction before it calls `QueryBegin` and does not end it when that
  hook throws (upstream: [duckdb/duckdb#25876](https://github.com/duckdb/duckdb/issues/25876)).
  An idle connection whose last statement was denied therefore holds a read snapshot until
  the next `Query`, `PendingQuery`, or `Prepare` call runs the engine's initial cleanup, or
  the connection is closed. Parse-only calls do not clean up: `extract_statements` (which
  Python's `execute()` calls before it executes) runs pragma preprocessing inside the leaked
  transaction, so a `PRAGMA` whose argument evaluation fails after a denial invalidates it,
  and every following `extract_statements` that contains a `PRAGMA` fails with `Current
  transaction is aborted` until a query entry point runs. Both effects are confined to the
  connection that received the denial.
- **Bind-time work inside trusted objects.** A view or macro the host defined over a reader
  opens files or URLs while the engine binds it, before the execution boundary can deny the
  statement (for example when that view is blocked by table policy). Object identity is a
  bind-time property, so this cannot move earlier. `enable_external_access=false` and
  `allowed_directories` are the controls; `CALL gatekeeper_enforce()` warns when they are loose.
- **Opaque Quack bodies and deferred binding.** Private catalog authorization refuses
  unsupported remote scope even through trusted definitions. A parameterized statement can
  nevertheless bind a remote view or a trusted body containing Quack SQL delegation before
  that private check and execute remotely. Native DuckDB 1.5 preparation of constant remote
  SQL can also transmit before any text hook. A later refusal does not undo that execution;
  these routes are unsupported. See the [Quack support matrix](quack.md).
- **`Prepare()` binds before it is decided.** DuckDB 1.5 binds a prepared statement before
  any extension hook runs; 2.0 runs the prepare as a statement whose text is checked first, but
  a statement the text admits is still bound before its pre-screen. Agent-written readers are
  denied before execution either way, but the bind of a statement that will be denied has
  already happened; with external access enabled, that bind can perform reader I/O whose only
  observable effect for the caller is the denial's timing. The replacement-scan gate does run
  during that bind and holds every substituted reader to the allowlist: a caller's `FROM 'file'`
  is refused before anything opens. On 1.5, with no statement text on record, so is a trusted
  view that names its file the same way; 2.0's gate has the text and knows the view's file is
  the view's.
  Such a view cannot be prepared on an enforced connection unless its reader is allowed;
  executing the statement directly (with or without parameters) binds inside the query,
  where the text is on record, and a view written with an explicit `read_parquet(...)` call
  is unaffected either way. The plan pre-screen after that bind has no record either, so it
  checks plan structure and Gatekeeper's control plane and defers table policy and the rest
  of function policy to execution: a prepared statement whose text names a denied table or a
  blocked or never-bind function prepares, and is refused when executed.
- **Preprocessor rewrites.** DuckDB rewrites query pragmas (`PRAGMA version`) into the
  `SELECT` they stand for before any hook. The rewritten statement is what Gatekeeper checks
  and what the audit record's `statement` holds; that is policy-consistent, but the raw text
  differs from what `gatekeeper_validate` would report (`unsupported` for the `PRAGMA`).
- **Dynamic `PIVOT` runs as a batch.** DuckDB's parser rewrites `PIVOT t ON col USING agg(x)`
  (no `IN` list) into `CREATE OR REPLACE TEMP TYPE "__pivot_enum_<uuid>" AS ENUM (SELECT
  DISTINCT CAST(col AS VARCHAR) FROM t ...)` per dynamic column followed by the `SELECT` that
  pivots on those types, and the engine runs each as its own statement
  (`Transformer::CreatePivotStatement`, `StatementPreprocessor`). Gatekeeper admits exactly that
  `CREATE`, by shape (`OR REPLACE`, `TEMP`, unqualified, that name pattern, defined by a query,
  not by literals) in both paths, checks its `SELECT` as any other, and requires the bound plan
  to be that `SELECT`'s under a `LOGICAL_CREATE_TYPE` root in the temporary catalog.
  `gatekeeper_validate` decides the same statements on the same text the engine will run, in
  the engine's order, stopping at the first denial, and creates nothing. What remains:
  - The enum is a real temporary type in the caller's session. The engine never drops it
    (an upstream `FIXME`), it is created before the pivoting `SELECT` is checked, and it stays
    when that `SELECT` is denied. It holds the distinct values of a column the policy let the
    caller read, in the caller's own temporary catalog, and nothing else can reach it.
  - On an enforced connection the audit trail is one record per rewritten statement, each on
    DuckDB's rewritten text rather than the caller's. Enforcement stops at the first denied
    record; log-only mode records every statement. `gatekeeper_validate` writes its usual one
    `validate` record, on the caller's text, carrying the decision described above.
  - The fixed text, AST, node, and depth limits apply to each rewritten statement, as an
    enforced connection applies them to each statement it runs. The expansion itself, one
    copy of the source per dynamic column, is DuckDB's parser's and happens for every
    connection before any hook; `gatekeeper_validate` then spends one check and one or two
    binds per rewritten statement, proportional to what executing the text costs.
  - Each rewritten statement is a statement to the engine, so each reads its own policy
    snapshot at `QueryBegin`, exactly as the statements of `SELECT 1; SELECT 2` do. A policy
    change that lands between the enum's `CREATE` and the pivoting `SELECT` governs the
    `SELECT`; nothing executes under a snapshot older than its own statement, and a denial
    then leaves only the temporary type above. `gatekeeper_validate` reads one snapshot for
    the whole text, as it does for any statement whose execution a later policy change can
    still refuse. There is no hook that spans the batch, so this is the boundary, not a gap
    in it.
  - The enum types do not exist when `gatekeeper_validate` binds the statements that name
    them (the pivoting `SELECT`, and the `SELECT` of a later enum when a dynamic `PIVOT` is
    nested inside another), so those are bound against placeholder `IN` lists instead, once
    per plan shape `Binder::BindPivot` chooses between by a `PIVOT`'s total number of values:
    filtered aggregates up to `pivot_filter_threshold` and a `list` aggregate under a `PIVOT`
    operator above it. The large shape is sized per `PIVOT` from its static `IN` lists and
    host enums so that it crosses the threshold and stays under `pivot_limit` wherever a legal
    `list` plan exists. Every plan the data can select at execution has therefore passed
    validation. The reverse does not hold: with `list` (or `concat`, for several pivot
    columns) in `blocked_functions`, `gatekeeper_validate` denies every dynamic `PIVOT` that
    has a legal `list` plan, while an enforced connection denies it only when the data has
    more distinct values than the threshold. The pivot's column count is also
    data-dependent, so text whose binding depends on it (a column alias list over the pivot,
    a set operation with it as an operand, a value count that reaches `pivot_limit`) can bind
    differently at execution than under the placeholders; the enforced connection binds the
    real type and is exact. DuckDB itself refuses to `PREPARE` a dynamic `PIVOT` for the same
    reason.
- **Enforcement is opt-in per connection.** A connection the host opens without running
  `CALL gatekeeper_enforce()` on it is trusted, with the whole engine available. That is what
  lets the host keep a connection for the audit log and policy changes, and what lets
  extensions that open connections internally for their own metadata SQL keep working; it also
  means the host's connection factory is part of the sandbox boundary.
- **Errors are informative.** Engine errors keep DuckDB's wording, which can name objects and
  paths the policy denies (`Did you mean "secret"?`). Gatekeeper's own denials name the rule
  and the denied function or object, and the [audit record](#audit-log) holds the caller's
  text. These are privileged host diagnostics, including errors inside secure-view bodies;
  see [host-only evidence](#secure-views-and-host-only-evidence) before relaying any projection.
  One engine error reads differently on an enforced connection: the engine binds a copy of the
  statement when a connection state can request a rebind, as Gatekeeper's does, and DuckDB's
  `PivotRef::Copy` drops the query location, so a binder error raised at a `PIVOT` (a value
  listed twice, the pivot limit) arrives without its `LINE n:` excerpt. The message is
  otherwise the same.
- **Not a resource sandbox.** Memory, CPU time, temporary disk, extension loading, and
  network posture remain host settings. Gatekeeper reports weak posture; it never changes it.

### Enforcement semantics

`CALL gatekeeper_enforce()` stores the enforced state in the connection's registered state at
execution time (never at bind, so `EXPLAIN` and `PREPARE` of it do not enforce). Nothing removes
it; `RESET`, `lock_configuration`, and native option writes cannot reach it because it is not a
setting. On an enforced connection `CALL`, `SET`, and `RESET` are unsupported statements, so the
enforced state and the policy are unreachable from SQL. `gatekeeper_enforce` is on the
never-bind list so validated SQL cannot name it either. Inside a transaction the host has
opened, the call is refused with a `Permission Error` and latches nothing: `COMMIT` and
`ROLLBACK` are not read statements, so an enforced connection could never end that
transaction. End the transaction, then enforce. (Whether the refused statement also aborts the
transaction is the engine's transaction-invalidation policy: DuckDB 1.5 leaves it usable after a
`Permission Error`; DuckDB 2.0 aborts it by default, so `ROLLBACK` first.)

There is deliberately no instance-wide enforcement setting. One would have to choose between enforcing the
host's own connections (leaving no in-process reader for the audit log and no way to change
the policy) and depending on connection-open ordering, and a setting is one more thing a
trusted connection can be talked into flipping. A connection is enforced because the host said
so on that connection, at that moment.

### Log-only mode

`SET gatekeeper_log_only = true` is a global BOOLEAN setting, default `false`, reversible, and
frozen by `lock_configuration`. While it is true, every enforced connection makes and records
every policy decision as it otherwise would, without refusing policy denials: a denial is
written to the log with `mode = 'log_only'` and the engine then binds and executes the statement as it would
on an unenforced connection. It exists so a policy can be measured against real traffic (what
would be refused, and what the traffic resolves to) before any of it is refused.

**Routing exception:** CONNECT/DISCONNECT on DuckDB 2.0 always retain `mode = 'enforce'`
and are refused at the text boundary, including client-prepared routes. Parsed statement
types select this exception before policy or size-limit failures can be waived by log-only.
Keeping the execution route LOCAL makes the rollout switch reversible and keeps audit
records about locally authorized execution. This does not protect against trusted native
state mutation or already-connected activation; the [host requirements](#connect-mode-and-native-host-state)
still apply. Other control-plane statements remain subject to normal log-only semantics.

Semantics that follow from "the same decision, without the refusal":

- The switch is read once per statement, in `QueryBegin` next to the policy, and snapshotted
  with it, so every boundary of one statement agrees; a flip applies at the next statement on
  every enforced connection, in both directions.
- The same policy checks: the text check, the private authorizing bind, the
  rebind of prepared executions, and the plan check all run. Log-only measures what enforcement
  would deny; 2.0 log-only additionally parses to identify routing controls.
- Exactly one record per statement, at the boundary that decided it, in both modes. Once a
  log-only statement has been decided, the hooks the engine reaches while binding and
  executing it anyway do not decide it again. The replacement-scan gate lets the engine's own
  bind through for a statement already decided; for one not yet decided (parameters defer
  authorization to the engine's bind, and a 1.5 `Prepare()` has no statement in progress) the gate
  records the denied reader itself, under the statement's snapshotted mode and policy, marks
  the statement decided, and then lets the bind continue. That ordering matters: a reader
  whose file does not exist fails the bind before any later hook runs, and the gate's record is
  the only trace of the would-be denial.
- Nothing from the private path surfaces. An engine error raised while Gatekeeper binds
  privately propagates on an enforcing connection (DuckDB's own message is the outcome); in
  log-only mode it is recorded as `gatekeeper_validate` reports it (`code = 'binding'`) and the
  engine's own bind raises the error, with the query location a hook cannot attach. When
  parameters defer the private bind and the engine's own bind fails first, the same record is
  written from the planning-error hook and the engine's exception propagates unchanged; a
  failure the engine raises before any plan exists (a parameter the caller did not supply) is
  recorded at query end, without a `query_id`. The caller sees exactly what an unenforced
  connection shows; `test/test_log_only.py` asserts
  this over the enforcement parity corpus on identical fresh instances, and asserts the record
  equals the `gatekeeper_validate` row.
- Apart from routing controls, a `Prepare()` is pre-screened as before and a denial there is recorded with
  `mode = 'log_only'` (on 1.5 with no statement text, on 2.0 with the prepared text); each
  later execution is its own record.
- **Log-only provides no policy protection, including for Gatekeeper.** Apart from the routing
  exception, on a log-only connection `SET gatekeeper_policy`, `CALL gatekeeper_configure()`,
  and `SET gatekeeper_log_only` are unsupported statements that are recorded and then execute.
  The connection stays enforced and LOCAL, so flipping the switch back restores policy refusals
  on it. `lock_configuration` is the mitigation,
  as for the policy; the `lock_configuration` posture warning names both settings, and
  `gatekeeper_enforce()` warns whenever the switch is on. Locking while the switch is on
  freezes it on: `SET allowed_configs = ['gatekeeper_log_only']` before locking keeps the way
  back to refusals. That exception is safe to leave open because of where an enforced
  connection can reach `SET` from: while the switch is off it is refusing, so `SET` is an
  unsupported statement and the agent cannot turn the switch on; while the switch is on,
  `SET gatekeeper_log_only = false` executes and restores refusals on that connection, after
  which `SET ... = true` is refused. The only change the exception hands an agent is turning
  refusals back on. The host, unenforced, moves the switch either way.
- Only a BOOLEAN `true` suspends refusals. A value written natively through
  `DBConfig::SetOption` without the `SET` callback is read as it is stored; anything that is
  not a BOOLEAN `true` (a NULL, a VARCHAR `'true'`) is enforcing. The unvalidated direction
  fails closed.

### Audit log

On an enforced connection the denial goes to the caller, not the host. What the host gets is a
record: every decision Gatekeeper makes, on an enforced connection or in `gatekeeper_validate`,
and every change to its global settings made through SQL (`SET`, `RESET`, `CALL
gatekeeper_configure`, `SET gatekeeper_log_only`), is written as a structured entry of DuckDB log type `Gatekeeper`. A native
`DBConfig::SetOption` write bypasses the `SET` callback and leaves no entry; the next decision's
`policy_hash` still changes. The record's decision columns are exactly `gatekeeper_validate`'s (`allowed`,
`code`, `violations`, `error_type`, `error_message`, `position`, `objects`, `functions`, `caller_objects`, `caller_functions`), so the
log and the function describe a statement the same way; `test/test_audit.py` asserts this over
the enforcement parity corpus. Each violation has fields in this order:
`rule`, `message`, `catalog`, `schema_path VARCHAR[]`, `table`, `function_name`,
`position BIGINT`, `function_type`, `object_type` (all other fields VARCHAR).
Known denied functions retain their catalog/schema/name identity and kind (`function_type`).
Resolved catalog-object denials retain `object_type = 'table'` or `'view'`, including
allowlist misses, explicit blocks, and `internal_object` denials. The `table` rule can deny
either kind. Each kind field is `''` when unresolved or inapplicable; replacement-reader
denials do not infer an object kind from their written path. `objects`, `functions`,
`caller_objects`, and `caller_functions` remain empty on failure. This applies equally to `validate`, `enforce`,
and `log_only` records returned by `duckdb_logs_parsed('Gatekeeper')`; consumers pinning
the STRUCT schema must include both trailing kind fields. The rest of the record is:

| column | meaning |
| --- | --- |
| `event` | `decision`, `policy_changed`, or `log_only_changed` |
| `mode` | `enforce` (an enforced decision, including CONNECT/DISCONNECT while log-only is on), `log_only` (a policy decision with `gatekeeper_log_only` true; the statement ran regardless), or `validate` (`gatekeeper_validate`) |
| `boundary` | where an enforced statement was decided: `binding` (text check), `authorize` (private bind), `execution` (the plan the engine will run), `prepare` (pre-screen of a `Prepare()` plan), `replacement_scan` (a reader resolved outside the private bind). NULL for `validate`, which runs the whole check at once. |
| `statement` | the SQL the engine ran, capped at 64 KiB (`statement_length` is the full size). NULL at `boundary = 'prepare'`, where no query is active and DuckDB exposes no text; the `violations` still name the object or function. For dynamic `PIVOT` and query pragmas this is DuckDB's rewritten text, not the caller's (see residuals). |
| `policy_hash` | sixteen hex digits over the canonical `gatekeeper_policy` value in force for the decision; the same hash appears on the `policy_changed` record that installed it, whose `new_value` is the full policy |
| `new_value` | the new setting value on `*_changed` records |

DuckDB's own log-context columns (`connection_id`, `transaction_id`, `query_id`) describe the
connection that ran the statement, not the one reading the log.

Denials and setting changes are written at `INFO`, allowed statements at `DEBUG`. The type's
declared level is `INFO`, so `CALL enable_logging('Gatekeeper')` records denials by itself; to
also record every allowed statement with the tables, views, and functions it resolved to, follow
it with `SET logging_level = 'debug'` (`enable_logging`'s own `level` argument is overridden by
the type's declared level when a type is named). Storage is DuckDB's: `memory` by default, or
`CALL enable_logging('Gatekeeper', storage := 'file', storage_path := '...')`.

```sql
CALL enable_logging('Gatekeeper');
SELECT timestamp, connection_id, boundary, code, violations, statement
FROM duckdb_logs_parsed('Gatekeeper') WHERE event = 'decision' AND NOT allowed;
```

Properties that make the record trustworthy as evidence:

- **Exactly one record per statement**, at the boundary that denied it or as `allowed` once the
  plan the engine will execute has passed. A `Prepare()` pre-screen that passes writes nothing.
- **The denied text exists only here.** DuckDB writes its own `QueryLog` entry after the
  `QueryBegin` hook, so a statement refused at the binding boundary never appears in `QueryLog`.
- **Records are written through the database logger, not the connection's.** A connection's
  logger is a snapshot of the log configuration, refreshed only after the `QueryBegin` hooks run
  and at query end; on a connection opened before `enable_logging` it would drop the first
  denial. The database logger tracks the configuration live, and the record is stamped with the
  statement's own connection, transaction, and query identity.
- **Engine errors are not decisions.** A missing table or a type error on an enforcing connection
  is DuckDB's error, in DuckDB's words, and is not recorded; `gatekeeper_validate` maps the same
  outcome to `code = 'binding'` and that call is recorded, and so is a log-only statement, whose
  record is what `gatekeeper_validate` would have said (the engine then raises its own error).
  When reading a log-only trail for what enforcement would refuse, every denied record except
  `code = 'binding'` counts: `forbidden` and `unsupported` are policy decisions, `invalid_input`
  is the text check's rejection of empty/NUL-containing input or a policy the host left
  unreadable through a native write (limits and multi-statement text use `forbidden`/`limit`),
  and `parser` is Gatekeeper's own parse failing on text the
  engine accepted, all of which strict mode refuses with a Gatekeeper denial. `binding` is the
  engine rejecting the statement, recorded only in log-only mode so the trail is complete. Text
  DuckDB's parser rejects fails before any hook and is recorded in neither mode.
- **The sandboxed connection cannot read, redirect, silence, erase, or forge the log.**
  `duckdb_logs`, `duckdb_logs_parsed`, `duckdb_log_contexts`, `enable_logging` (whose
  `storage_path` writes a file of the caller's choosing), `disable_logging`,
  `truncate_duckdb_logs`, and `write_log` (which writes any message under any log type,
  `'Gatekeeper'` included) are on the never-bind list, so no policy can admit them; `SET`,
  `RESET`, and `CALL` are unsupported statements. `CALL gatekeeper_enforce()` warns when logging
  would not record a denial. One path is outside this control and is listed under residuals:
  DuckDB's `PRAGMA` preprocessing evaluates argument expressions before any hook, so on an
  enforced connection without validate-first, `PRAGMA x(write_log(...))` can plant a
  `Gatekeeper`-typed entry before the statement is denied. A malformed one makes
  `duckdb_logs_parsed('Gatekeeper')` fail for the reader; a well-formed one is a forgery.
  Hosts that need the log as evidence against an adversarial caller should validate first,
  which keeps `PRAGMA` text away from the preprocessor entirely, and can read the raw
  `duckdb_logs` rows with `TRY_CAST` if a malformed entry must be tolerated.
- **The host's own changes are on the record.** `SET` and `RESET` of `gatekeeper_policy` and
  `CALL gatekeeper_configure` each write a `policy_changed` entry, and of `gatekeeper_log_only`
  a `log_only_changed` entry (a `RESET` reports the default value). A native `DBConfig::SetOption` write bypasses the `SET`
  callback and writes no entry, but the next decision's `policy_hash` changes, so a policy that
  was altered that way is still visible.
- Log writes are not guarded: if the configured storage fails (an unwritable file), the
  statement fails with that error rather than executing unrecorded, and a setting change whose
  record cannot be written is not applied (the record is written before the setting is
  published).

The record names rules, objects, functions, and the caller's text; treat the log as sensitive.

## Function enforcement and trusted expansion

Caller-authored function names pass the AST allowlist. Unambiguous syntax such as
list construction and slicing adds `list_value`/`array_slice` to that check.
Ambiguous indexing, dotted references, arrows and SQL-value names record the possible
implementations; the catalog callback checks the implementation DuckDB actually
selects. `t.column` and a real column named `current_schema` are not automatically
treated as functions. Parser/binder rewriting may select an extraction helper for JSON syntax;
the selected entry has its own exact grant/block identity.

Function allowlisting cannot be disabled. Each policy layer admits its explicit qualified
`allowed_functions` plus the reviewed defaults when `use_default_functions` is true;
explicit blocks and the never-bind list take precedence for what the caller writes.
`blocked_functions` has the same STRUCT/object shape as grants: optional catalog, required
exact-depth `schema_path`, required exact `name`, and optional `type`. Namespace wildcards are explicit;
the leaf `*` is multiplication, not all functions. Omitting the name cannot grant a schema;
schema-wide function permission is unsupported. Defaults carry exact catalog/schema/name/kind identities from
the reviewed inventory, so another kind in the same namespace cannot borrow a default.
Pre-resolution refusal requires that blocks cover every eligible identity for the leaf; a scoped
block leaving another eligible identity waits for the actual catalog entry, before its bind callback.
Unknown attributable provenance fails closed; absence of a matching block is never authorization.
Never-bind and control-plane restrictions remain separate pre-resolution checks with their existing
origin rules. See [qualified function rules](qualified-functions.md) for direct-binding and preparation limits.

Explicit grants for internal functions require every schema component to be exact. Catalog
may be omitted, NULL, or `*`; kind remains optional and name is always exact. Block rules keep
their namespace wildcards. This uses the actual `CatalogEntry::internal` flag, not an assumption
that every `system.main` entry is internal: non-internal extension entries can use schema-pattern
grants. Bound descriptors recover the flag only from exact observed-entry provenance or reviewed
source-defined intrinsics/substitutions. Unknown internal origin cannot use schema-wildcard grants.
Reviewed defaults already carry exact identities; the flag is not added to public evidence.

Configurable grants and blocks match **exact catalog-entry names without alias canonicalization**.
This includes Parquet (`read_parquet` / `parquet_scan`), JSON extraction (`json_extract` /
`json_extract_path` / `->`, and `json_extract_string` / `json_extract_path_text` / `->>`), and
window entries (`rank_dense` / `dense_rank`, `first_value`, `last_value`).
Cover each intended entry explicitly. Parquet file shorthand selects `parquet_scan`; granting
`read_parquet` alone does not authorize that replacement reader. Pre-resolution refusals preserve
the screened spelling; resolved violations and successful dependency lists retain observed identities.
A caller's host `read_parquet` macro likewise does not make a trusted body's system `parquet_scan`
reader caller-attributable, or vice versa.

Source-defined parser/binder rewriting is an attribution mechanism, not general semantic equivalence
or a configurable policy alias. Authorization follows parsed operations and selected entries.
DuckDB 1.5 maps `first/last OVER` to the `first_value/last_value` intrinsic implementations,
which Gatekeeper authorizes as windows, matching 2.0's parser rewrite. The real `first/last`
aggregate entries retrieved by 1.5 still require separate authorization and appear in evidence;
a kindless block on those names therefore still denies that shorthand on 1.5 only. See
[qualified function rules](qualified-functions.md) for the engine-specific details.

**Trusted definitions are opaque to table and function policy.** A view, scalar macro, or
table macro the host created (any non-internal catalog entry), and an attached catalog's tables and views with
the scans the catalog uses for them, are trusted definitions. What their bodies introduce is
theirs, not the caller's: an explicit `read_parquet(...)`, a file path (`FROM 'x.parquet'`),
`md5`, `list_sum` and the `sum` it dispatches, the `lower` behind a `COLLATE nocase`,
`duckdb_tables()`, `iceberg_scan`, and every table and view the body reads, internal views
included. None of it is subject to the function allowlist, to `blocked_functions`, to the
never-bind list, to `allowed_tables`, to `blocked_tables`, or to the internal-object rule; a
host view over `duckdb_settings()` is the host's decision to expose settings, and a host view
over `secret.t` is the host's decision to expose those rows. This exemption does not bypass
independent control-plane or supported-execution-scope checks. Gatekeeper's own control plane
(`gatekeeper_configure`, `gatekeeper_enforce`,
`enable_logging`, `disable_logging`, `truncate_duckdb_logs`, `write_log`,
`ControlPlaneFunctions()` in `src/include/function_policy.hpp`) is refused on every route: a
definition over one of these would let a `SELECT` rewrite the policy or erase its own record,
which no definition legitimately intends. Private catalog authorization also refuses opaque
Quack SQL functions and remote views even when a trusted body reaches them; on DuckDB 1.5,
all attached Quack objects are refused. These are unsupported-scope refusals, not ordinary
function or table blocks reaching inside a trusted definition. Deferred trusted-body binding
can execute remotely before the private check, so a later denial is not proof of zero remote
I/O. See the [Quack support matrix](quack.md) for supported base-table reads and preparation limits.

Table and function policy govern what is attributable to the caller.
For objects: the view or table the caller names, checked by resolved identity, and every
object the caller's own binders retrieve or the caller's text names, wherever that name
binds. For functions: the names in the caller's text, the names the caller's own binders
retrieve while binding it (the default macros a caller-written name expands to, such as
`list_sum` to `list_aggr`, and everything those name in turn), the aggregate a
caller-attributable dispatcher selects, and the collation functions when the caller wrote
`COLLATE`. A macro must itself be allowed by name. The exemption is by origin, not by name:
the same function written by the caller next to a view that also uses it is the caller's,
the same table the caller reads next to a view that also reads it is the caller's, and the
caller's rules then apply query-wide, since the bound plan carries no scope. A CTE or alias
the caller reads under a name a definition also reads counts as naming that object: the
walk records what was written, not what it resolved to.

Origin is established during the private bind. DuckDB copies a binder's catalog-lookup
callback into every child binder it creates and creates the binder for a view or table
macro body right after retrieving that entry, so Gatekeeper's callback carries scope:
retrieving a host view or table macro arms the copy that made the lookup, the next copy
made from it (the body's binder) starts trusted, and trusted copies beget trusted copies.
Lookups a trusted copy makes are the definition's own. A scalar macro body binds in the
caller's own binder, so its names and table references are learned from its definition: the
macro's expression and default arguments are walked by the same grammar walker as the
caller's text, and a name it introduces, or a table its subqueries read, is the macro's
unless the caller can produce it too, in its text or through a default macro its text
expands to (the caller's `list_count` names `list_aggr` without writing it, and a host
macro over `list_sum` does not make that `list_aggr`, or the `count` it dispatches, the
macro's). Caller-written CTEs a table macro inherits are the caller's text bound in the
caller's scope, and a table-function argument is a literal or a parameter before anything
binds, so no caller-written table reference reaches a trusted body's binder. The execution
boundary then applies function policy only to names the record attributes to the caller and
table policy only to identities it does, holding the engine's plan to the tables, table
functions and scan counts of the private bind's plan; an attached table's scan (`LogicalGet`
with a table entry) is never attributed as a function. A table function a trusted definition
named binds what it replaces itself with as that definition's: `query_table(n)` in a host
scalar-macro body selects the macro's table, as it does in a table macro's body. A `Prepare()`
has no record of who wrote what (on 1.5 it binds outside any statement, with no text at all);
its pre-screen checks plan structure and the control plane and defers table policy and the
rest of function policy to execution, which rebinds inside the query.

The callback exposes no expression origin within one binder: when caller syntax requires
an implementation check, a trusted expansion using the same implementation must also pass
it. This conservative query-wide restriction can deny a mixed caller/view expression; it
does not grant an exception to caller code. Type names, casts, and collations are trusted
host database configuration and are not authorized separately. Trust covers the whole
body, arguments included: a host macro that forwards a caller argument into a reader
(`CREATE MACRO files(p) AS TABLE SELECT * FROM read_parquet(p)`) hands the caller that
choice, and neither the allowlist nor `blocked_functions` stands in the way; one that
forwards it into a table lookup (`CREATE MACRO peek(n) AS TABLE SELECT * FROM query_table(n)`)
delegates table selection to the caller through the host's trusted capability, and the
caller's own `allowed_tables` and `blocked_tables` do not apply to what it selects. Do not create
pass-through definitions for capabilities the policy is meant to withhold; DuckDB itself
refuses a macro that forwards an aggregate name into a dispatcher, since the name must be
a constant.
Name-selected aggregate dispatch (`list_aggregate`, `list_aggr`, `aggregate`,
`array_aggregate`, `array_aggr`) is elevated, and admitting a dispatcher does not admit
every aggregate it can reach: when the caller writes one, the aggregate DuckDB resolves
from the caller's literal name argument must pass both qualified allowlists before private binding, and like other
ambiguous caller syntax the check applies query-wide, so a trusted view's own dispatch in
the same plan is checked too. Dispatchers used only inside trusted definitions, and the
fixed `histogram` behind `list_distinct`/`list_unique`, are those definitions' own.

Defaults authorize reviewed identities in `system.main` only. A host-created macro or function
shadowing a default needs an explicit qualified grant; once authorized, a host macro's body
retains the trust described above. Types, casts, and host default collations remain trusted
configuration. Catalog integrity remains a prerequisite; namespace pinning does not make
untrusted DDL safe. See [qualified grants and feasibility](qualified-functions.md) for the
exact name/kind matching contract, intrinsic provenance, and direct-binding limits, and the
[policy v2 migration guide](policy-migration.md) for input changes.

Source-backed binder substitutions retain the origin of the selected definition on both engines:
collated `min`/`max` can select `arg_min`/`arg_max`, `date_part`/`datepart` can select
`epoch`/`julian` on 1.5 or any constant unary date part on 2.0 (including `year`, `dayofweek`,
and `microsecond`), and `quantile` can select `quantile_disc`. Caller substitutions obey qualified
blocks and, in each layer with defaults disabled, require implementation grants in addition
to source grants. These are implementation dependencies, not policy aliases; a grant for
`min` alone does not grant `arg_min`. The same substitutions introduced solely by trusted
definitions remain those definitions' own. Missing or ambiguous caller implementation
provenance fails closed; see [binder substitutions](qualified-functions.md#binder-substitutions-and-specialization).

Quantile fraction/options restrictions apply after catalog resolution selects a caller-attributable
`system.main` aggregate, before its private bind callback. They require literals or bindable
parameters in an unqualified positional call. Named-argument and dotted/method calls, including explicitly qualified system
quantiles with literal fractions, are conservatively refused because the lookup hook supplies
no occurrence-to-argument mapping and named arguments can be reordered by the selected signature.
This applies to window aggregates too. Granted host functions/macros with quantile-like names retain
their own argument contracts, subject to the native callback provenance restrictions above.
List aggregate dispatchers similarly refuse named mappings after system resolution.
An earlier engine resolution error can therefore return `binding` before
the quantile check is reached; see [quantile contracts](qualified-functions.md#quantile-argument-contracts).

Caller syntax still has conservative implementation checks: with defaults disabled,
`SELECT * FROM v_st` may pass but
`SELECT t.x FROM t, v_st` may fail because the view uses `struct_extract`. Whole-row
`SELECT t FROM t` needs `struct_pack`; single-part references therefore enable its
query-wide check too. Single-arrow function-child `x -> ...` remains ambiguous: DuckDB
can fall back to JSON binding even inside a function argument. Such syntax retains
the conservative `json_extract` candidate. Use `lambda x: ...` to avoid that ambiguity
when combining lambdas with trusted JSON expansions.

### Never-bind functions

The explicit list in `src/include/function_policy.hpp` contains:

```
checkpoint currval force_checkpoint nextval gatekeeper_configure gatekeeper_enforce
query query_table quack_query quack_query_by_name json_execute_serialized_sql json_serialize_plan read_duckdb seq_scan which_secret
enable_logging disable_logging truncate_duckdb_logs write_log
pragma_collations pragma_database_size pragma_metadata_info pragma_show
pragma_storage_info pragma_table_info pragma_table_sample
duckdb_approx_database_count duckdb_columns duckdb_connection_count duckdb_constraints
duckdb_coordinate_systems duckdb_databases duckdb_dependencies duckdb_extensions
duckdb_external_file_cache duckdb_functions duckdb_indexes duckdb_log_contexts
duckdb_logs duckdb_logs_parsed duckdb_memory duckdb_prepared_statements
duckdb_profiling_settings duckdb_schemas duckdb_secret_types duckdb_secrets
duckdb_sequences duckdb_settings duckdb_table_sample duckdb_tables
duckdb_temporary_files duckdb_types duckdb_variables duckdb_views
```

It governs what the caller's text reaches, directly or through the implementations
binding derives from it; a host view or macro that uses one of these is a trusted
definition, exempt from the caller never-bind rule. Independent control-plane and
supported-execution-scope checks still apply. The control-plane subset (`gatekeeper_configure`,
`gatekeeper_enforce`, `enable_logging`, `disable_logging`, `truncate_duckdb_logs`,
`write_log`) is refused on every route. Private catalog authorization also refuses
`quack_query`, `quack_query_by_name`, and unsupported Quack objects reached through trusted
bodies. Deferred binding can execute remotely before that check; see the
[remote support matrix and residuals](quack.md).

Source review at the pinned revision: `src/function/table/query_function.cpp`
reparses dynamic SQL/names; `read_duckdb.cpp` attaches hidden databases;
`src/function/table/system/` readers inspect catalogs, secrets, storage or session
state outside table authorization; `checkpoint.cpp` and `scalar/sequence/nextval.cpp`
mutate or inspect storage/sequence state. `seq_scan` is the internal scan entry,
not a caller capability (normal physical scans retain object authorization).
`gatekeeper_configure` mutates the global policy and `gatekeeper_enforce` enforces it on the
connection; both are always forbidden in submitted SQL, including resolved table-function
uses inside trusted views/macros.
`enable_logging`, `disable_logging`, and `truncate_duckdb_logs`
(`src/function/table/system/logging_utils.cpp`) reconfigure, silence, or erase the log
that records Gatekeeper's own decisions, and `enable_logging(storage_path := ...)` writes a
file at a caller-chosen path; `write_log` (`src/function/scalar/system/write_log.cpp`)
writes an arbitrary message under any `log_type`, `'Gatekeeper'` included, so it could forge
a decision record or plant one `duckdb_logs_parsed` cannot cast. The
[audit log](#audit-log) is evidence only if the sandboxed side cannot reach any of them
under any policy.
JSON SQL execution is defined in `extension/json/`. `pragma_table_sample` is a
reserved defensive spelling; the pinned registration is `duckdb_table_sample`.
Static `duckdb_keywords`/`duckdb_optimizers` are deliberately not prefix-denied.
All listed names are excluded from defaults and cannot be admitted by options.
Metadata views the caller names (`information_schema.tables`, `duckdb_tables`) expand to
these readers and are denied even with exact `allowed_tables` rules for the view: the
internal view is the caller's, so its reader is the caller's and never-bind. This is
deliberate: metadata readers enumerate across catalogs and cannot be row-filtered by
object callbacks. Tenant introspection must use a host-controlled API: a host view or
macro over such a metadata view is one, its reader is the definition's own, and exposing
it is the host's decision.
`json_serialize_plan` is listed because it binds and plans caller-supplied SQL at
execution time, outside this validation.

### Callback bypasses

Gatekeeper does not authorize type names or cast implementations. Caller COLLATE implementations
that survive binding are authorized by qualified scalar identity: 1.5 recovers missing stamps only
from the exact caller-selected system collation entries; 2.0 supplies qualified scalar implementations.
This is not a collation-name allowlist or a pre-callback interception surface.
The database owner controls extension loading and definitions. Table/view catalog
and schema restrictions do not restrict type lookup. There is no mandatory type audit.
Type resolution can autoload or autoinstall extensions when enabled; hosts must
provision extensions during trusted setup and disable `autoload_known_extensions`
and `autoinstall_known_extensions` on validation connections.
Built-in temporal casts can use ICU timezone/calendar settings; GEOMETRY CRS binding
can consult trusted CRS providers and `ignore_unknown_crs`.

- `bind_pivot.cpp` performs direct aggregate and enum lookups. Explicit aggregate
  names pass preflight; named PIVOT enums use the host's type definitions. A dynamic
  PIVOT's own enum is created from a SELECT that passes every check first (see residuals).
- `bind_window_expression.cpp` and `function_binder.cpp` contain direct aggregate/
  function lookup paths. Caller names pass preflight; surviving bound scalar,
  aggregate, window and table functions also pass a resolved-deny plan walk, and the
  plan may contain only reviewed read-only logical operators.
- `collation_binding.cpp` directly loads collation entries and binds their scalar
  functions. Collation names and inferred implementations are not checked in preflight.
  The generic resolved-function deny walk still applies to surviving bound functions
  attributable to the caller, including implementations introduced by a `COLLATE` the
  caller wrote; a collation a trusted definition applies is that definition's. It is not
  a collation policy.
- The plan walk cannot undo bind-time work or see functions already folded away.
  Host default collations, trusted extension callbacks, custom casts/type binders,
  macro expansion internals and optimizer rewrites are not a complete execution
  interception surface. In particular, global blocks are not a sandbox for arbitrary
  trusted callback code that performs its own direct lookups/evaluation.

The bound-plan authorization module also checks SELECT-list `UNNEST`, executable
list lambda bodies (including collation implementations inside them), and list
aggregate implementations such as `sum` inside `list_sum`. DuckDB stores lambdas
and list aggregates in function bind data rather than ordinary expression children.
Lambda bodies are walked directly; the private list-aggregate bind data is inspected
through its pinned serialization callback, without evaluating or rebinding arguments.
The `system.main` list-lambda builtins (`list_transform`, `list_filter`, `list_reduce`,
and their aliases) always carry lambda bind data; if a build cannot recognize it (for
example a runtime-type mismatch across the host/loadable boundary on an untested
platform), validation fails closed with a `binding` error rather than skipping the body.
Both list-aggregate serialization and fixed histogram inspection require the bound
function's `system.main` provenance. Same-named scalar implementations from other
catalogs/schemas are opaque host functions: their private bind data is never inspected or serialized
as a system dispatcher. Caller use still requires its own qualified grant.
`list_distinct`/`list_unique` and their `array_*` aliases use the source-reviewed fixed
`histogram` implementation.
These implementations obey blocks in both layers and appear in successful function
evidence. Known identities retain catalog/schema; source-backed intrinsics have explicit system
identities. Unknown caller implementations refuse rather than satisfying a grant by leaf. Unknown
trusted-body dependencies can still appear with empty namespace. See the narrowly scoped
definition recovery in [qualified-function feasibility](qualified-functions.md#binder-substitutions-and-specialization). Arbitrary extension
bind data is not introspected.

## Remaining boundaries

- Validation always binds on the calling connection and authorizes the retrieved table
  and view identities attributable to the caller; what a trusted view or macro reads is
  recorded, not checked against table allow/block rules, so a host definition is the host's
  decision to expose what it reads within the supported execution scope. Independent
  control-plane and [Quack scope checks](quack.md) still apply. No public syntax-only mode
  exists. Function matching uses qualified identity, not a proof of a macro/UDF's implementation;
  catalog integrity is assumed.
- Trusted catalog code and attached tables may invoke elevated readers internally.
  Backing-file reads for an authorized logical table are allowed. Binder callbacks
  identify tables without depending on a particular scan operator. Local Iceberg
  REST/RustFS and DuckLake integration tests verify this boundary; other catalog
  implementations still need verification.
- Binding may perform remote I/O or evaluate bind-time expressions before returning,
  even for a request eventually denied. Caller-authored prohibited functions are
  rejected first; trusted expansions are outside function policy, Gatekeeper's control
  plane excepted. Lookup-triggered autoload can occur before the callback; use
  the host settings above, even for names included in the default inventories.
- No row/column authorization or execution-time memory/time/result limits.
- Default functions are reviewed qualified identities, not a proof of harmlessness for
  every overload or argument. Existing DuckDB implementations are trusted across
  engine upgrades; the inventory is not an exact-version compatibility gate. New
  names remain excluded until classified or explicitly allowed. The inventory admits the clock (`now`,
  `current_date`, `uuidv7`), non-cryptographic PRNG state including `setseed`'s reseed of
  the connection-local engine, and the host's `TimeZone`/`Calendar` settings that ICU
  temporal functions consume; results using them are not reproducible from SQL text
  alone, and a host that caches or replays tenant queries must account for that. All
  other catalog, session, configuration, or planner state is opt-in; see
  [inventories/README.md](../inventories/README.md#classification-criteria).
- Database-wide replacement scans are decided by a Gatekeeper callback installed first in DuckDB's
  database-wide replacement-scan list. It runs while a validation is binding on the calling thread
  and on every enforced connection; ordinary connections are unaffected. Other callbacks only construct a table
  reference, so a denial happens before the substituted reader binds and no file is
  opened. Readers substituted by DuckDB are authorized by their resolved names
  (`parquet_scan`, `read_csv_auto`, `read_json_auto`); each requires its own exact entry
  permission, independently of `read_parquet`, `read_csv`, or `read_json`.
  DuckDB 2.0 connection-scoped callbacks precede this gate; see the
  [compatibility limitation](#compatibility-and-review) below.
  No separate replacement-scan toggle exists. The check
  applied depends on who wrote the name: a table name in the caller's text (quoted or not,
  in any clause, including `DESCRIBE`, `PIVOT`, CTEs and subqueries) is the caller's reader
  choice and must pass every allowlist layer; a name reachable only through a view or
  macro body is that trusted definition's reader, outside function policy exactly as an
  explicit `read_parquet(...)` in that body is. The
  callback receives only the name, so the text walk records every table name the caller
  wrote and the gate consults that record (the private bind's, or the admitted statement's
  on an enforced connection); a name both sides use is checked as the caller's. On DuckDB
  1.5 a `Prepare()` bind outside any statement has no text on record and is pre-screened as
  though the caller wrote every name (2.0's prepare carries the text, and the gate consults
  it); the rebind hook then rebinds inside the query, where the record exists.
  Host-language scans that resolve to subqueries are always denied. When no callback
  claims a name, Gatekeeper raises the engine's missing-table error itself rather than
  returning to DuckDB's loop, so host callbacks are invoked exactly once per lookup and
  only behind this authorization; DuckDB's autoload retry and `FileExists` probe do not
  run. The one exception is a [log-only](#log-only-mode) statement not yet decided when
  the engine's bind reaches the gate: a claimed replacement is recorded and handed back as
  produced (still once per lookup), and an unclaimed name returns to DuckDB's loop, which
  asks the declining callbacks again and then resolves the name exactly as an unenforced
  connection would. If a catalog without transactional DDL finds the object on that lookup, the
  validation fails closed with a `binding` retry error rather than resuming the loop. The callback is keyed to the validating connection and nested validations
  restore the outer scope, so reentrant host callbacks cannot disable interception.
  Catalog objects with file-shaped names use ordinary object policy; unclaimed
  names return binding errors without file-name heuristics.
- Direct readers are controlled by function policy. There is no reader-argument
  inventory or local/remote path policy; admitting a reader permits its resource
  access. Resolved bindings do not provide an argument-level sandbox.
- Explicitly admitting eligible elevated readers transfers responsibility
  for their resources and trusted implementation to the application. The never-bind
  list cannot be overridden by any option for what the caller writes; a host definition
  over one of its entries is the host's decision, Gatekeeper's control plane excepted.
- A fixed internal cap rejects multiple statements before binding with code `forbidden`
  and violation rule `limit`; empty or comment-only SQL returns `invalid_input`.
- Fixed internal limits cap SQL input and serialized AST size at 8 MiB, AST traversal
  at 100,000 nodes, and AST depth at 512. AST validation occurs after parsing and
  serialization; traversal limits do not replace process limits against
  parser/serializer resource exhaustion.
- Engine diagnostics are returned verbatim in `error_message` for `parser` and `binding`
  results. DuckDB's messages can name catalog objects (`Did you mean "secrets"?`), file
  paths, and reader arguments, including objects the policy denies. Policy denials
  (`forbidden`, `unsupported`) carry no engine text. Treat `error_message` as sensitive:
  it is already in the [audit record](#audit-log) for operators, so return a generic error
  to untrusted callers. Trimming the
  message is not a reliable confidentiality boundary, because names can appear on any line.

Keep external access, extension loading, credentials, filesystem/network permissions,
and configuration changes controlled independently.

## Validating-connection profiles

Provision extensions, trusted catalogs/credentials, and Gatekeeper defaults before
locking configuration. Keep `search_path`, `USE`, attached catalog identities,
relevant parser settings, and trusted definitions aligned with execution. In-memory
and temporary objects belong to their connection/database context; a separate
validator cannot assume identical names refer to identical objects.

For a local-only deployment, after trusted setup:

```sql
SET enable_external_access=false;
SET autoload_known_extensions=false;
SET autoinstall_known_extensions=false;
SET memory_limit='512MB';
SET threads=1;
SET search_path='memory.reporting';
CALL gatekeeper_configure(allowed_tables := [{catalog: 'memory', schema_path: ['reporting'], 'table': '*'}]);
SET lock_configuration=true;
```

For trusted Iceberg/DuckLake or reader-backed views, keep external access enabled
where required. Install/load extensions and attach catalogs through trusted bootstrap,
scope credentials and network/filesystem access outside DuckDB, then disable autoload
and autoinstall, choose an application-appropriate memory limit, set `threads=1`, align
the search path, and finally lock configuration. Gatekeeper never changes these host
settings on behalf of a query. Test the profile against the particular catalog.

`memory_limit` is not a hard process RSS bound; use process/container memory limits,
timeouts/cancellation and isolation for hostile input. Literal-only preflight prevents
the reviewed computed-expression forms at LIMIT/OFFSET, table-function arguments,
AT, COLUMNS, PIVOT, quantile fractions, UNNEST options and type parameters. It does
not cap literal sizes beyond AST/input limits or prevent all evaluation inside trusted
definitions and function/type binders. No runtime-discovered allowlist is introduced.

Successful dependency lists are useful audit evidence, not a TOCTOU solution. They
record observed lookups and surviving function implementations, may omit hidden
extension work, and do not hash definitions or identify overloads. Failed decisions
return empty lists to avoid presenting an incomplete dependency set as authorization.
Omitted/NULL catalogs and `catalog: '*'` in `allowed_tables` include `temp` shadow tables. Table macros may
inherit caller CTEs whereas views do not; the CTE is the caller's text and is authorized as
such, so compare actual resolved objects rather than assuming definition-time bindings. User-defined enum types can expose all their labels
via `enum_range`, even when no table is read; type definitions are host-trusted data.

## Compatibility and review

Release binaries target DuckDB 1.5.6. Source builds may use another engine checkout;
the grammar and serializer come from that checkout, and DuckDB enforces binary
compatibility through the extension footer. That footer check can be disabled with
`allow_extensions_metadata_mismatch`, so Gatekeeper also records the engine it was built
from (the version tag for releases and prereleases such as `v2.0.0-alphaN`, the source id for
`-dev` builds, mirroring DuckDB's own footer identity) and refuses to load into any other engine. The stamp is a single string
(`strings gatekeeper.duckdb_extension | grep GATEKEEPER_BUILD_ENGINE`). The host's identity
is read from its catalog (`pragma_version()`) rather than `DuckDB::LibraryVersion()`:
distributed loadables statically link their own DuckDB copy, so the latter only ever
reports the build engine. A grammar generated from one engine must never validate
statements for another. Gatekeeper also compiles DuckDB's in-tree JSON serializer
(`extension/json/json_serializer.cpp`) and uses internal binder entry points
(`Binder::CreateBinder`, `SetBindingMode`, `SetCatalogLookupCallback`,
`GetReplacementScans`) and bind-data serialization callbacks; none of these are stable
public API, so an engine upgrade can require source changes. Compatibility is therefore
checked by compilation and functional regressions on every candidate engine
(`compatibility.yml`: a post-release snapshot of the pinned line and a `v2.0-cyanoptera`
snapshot), through both the direct CMake path and the community `make release` path. Existing function classifications do not
need repeating for each engine version. Unknown serialized fields and
node classes fail closed. Cast types use latest `UNBOUND(TypeExpression)` decoding,
including nested type parameters. Computed type parameters remain conservatively
unsupported. Ordinary literal payloads remain data, not executable nodes.

The same source builds against DuckDB 2.0 (`v2.0-cyanoptera`); `src/include/engine_api.hpp`
adapts the engine APIs that differ, and `scripts/generate.py` reads either release's
serialization schema. Both engines enforce the same policy model, with engine-specific
capabilities, conservative refusals, and diagnostics. These differences are worth knowing:

- 2.0 has only the PEG parser; the 1.5 `postgres` leg does not exist there.
- 2.0 connection-scoped replacement callbacks (including C API v2 registrations) run before
  database-wide callbacks. Gatekeeper's early replacement gate covers only the database-wide
  list. Ordinary catalog checks can still refuse a returned reader before its bind, but an
  otherwise admitted replacement can bind before the final unrecorded-scan backstop refuses it.
  This is not a pre-reader-I/O guarantee for connection-scoped replacements. Hosts requiring
  that guarantee must use database-wide registrations; connection-scoped interception needs
  a separate implementation and native callback-counter coverage.
- Named-parameter/session-variable collisions on 2.0 require `getvariable` permission before
  binding, even with explicit inputs during enforcement; see [parameter fallback](parameter-fallback.md).
  DuckDB 1.5 has no such fallback path.
- Native callback provenance and implementation substitutions differ: 1.5 refuses untrackable
  caller non-system bind callbacks and conservatively attributes possible system replacements;
  2.0 retains definitions. `first/last OVER` additionally checks the actual aggregate lookup on
  1.5. See [qualified-function differences](qualified-functions.md#binder-substitutions-and-specialization).
- Quack attached-object reads are refused on 1.5; supported 2.0 local base-table reads require
  pushdown disabled and checked table provenance. See the [Quack matrix](quack.md).
- Diagnostic positions are best-effort parser byte offsets. In particular, a caller table
  function in `FROM` may have a NULL violation position on 2.0 where 1.5 supplies an offset.
- 2.0 parses data-modifying CTEs (`WITH d AS (DELETE ...)`) that 1.5's parser refused; the
  grammar does not know their query nodes and refuses them as `unsupported`.
- 2.0's `SHOW name` can read a setting's value at bind time when no such table exists, with
  no function for the never-bind list to see, so that kind is refused; `DESCRIBE name` is
  the supported spelling. `SHOW TABLES` and the other catalog-wide forms still bind to
  never-bind readers and are refused as before.
- 2.0 runs `Prepare()` and `Execute()` from client APIs as statements carrying the prepared
  text. A prepare's plan is pre-screened as under 1.5 (its parameter values are not known) and
  each execution is authorized with its values under the policy in force then. Because the
  prepare carries the text, the text boundary applies to it: parameterless text is authorized
  privately at the prepare, as any parameterless statement is, so a statement the policy denies
  is refused at `Prepare()` rather than at its first `Execute()`; and the prepare's replacement
  gate knows the text, so a `FROM 'file'` inside a trusted view is not over-refused at prepare
  time as it is on 1.5.
- 2.0 produces a `SELECT`'s rows only as the client reads them, and runs `CALL` at once by
  marking the statement. `gatekeeper_enforce` and `gatekeeper_configure` set the same mark from
  their bind, so `SELECT enforced FROM gatekeeper_enforce()`, a prepared statement over either
  function, and `EXECUTE` of one run when the statement runs, whether or not the host reads the
  row; an unread `SELECT ... FROM gatekeeper_enforce()` would otherwise have left the connection
  unenforced while the host believed it latched.
- 2.0 supports nested schemas. Gatekeeper preserves written identifier components until binding,
  and uses the resolved full schema ancestry for authorization, provenance, scan accounting,
  and evidence. Three-part names can denote a nested schema without a catalog qualifier;
  they are not assumed to be `catalog.schema.table`. Policy and result `schema_path` fields
  have the same array type on 1.5, whose schemas have one component.
  The tested 2.0 snapshot does not allow nested schemas in `USE`/`search_path`; qualify nested
  names explicitly. Text-level refusals have no resolved catalog/schema identity (`''`/`[]`).
- 2.0 secure views are admitted with ordinary view identity and trusted attribution while
  preserving DuckDB's optimization boundary. Their transitive evidence and diagnostics remain
  [host-only](#secure-views-and-host-only-evidence).
- 2.0's default transaction-invalidation policy aborts an open transaction on any error,
  including a Gatekeeper refusal (1.5 kept it usable after a `Permission Error`). Enforced
  connections never hold one, so this only concerns hosts refusing `gatekeeper_enforce()`
  inside their own transaction, which then `ROLLBACK`.
- A refusal at the text boundary is thrown from DuckDB's `QueryBegin` hook, after the engine
  began the statement's auto-commit transaction and before it can end the query. On 2.0 that
  leftover transaction is invalid, and a statement the engine preprocesses inside a transaction
  before the next cleanup (a rewritten `PRAGMA`, a dynamic `PIVOT`, a relation-API statement)
  fails with "Current transaction is aborted" if it directly follows a refusal on the same
  connection; any plain statement in between clears it. This is engine sequencing in
  `ClientContext::BeginQueryInternal`'s caller, related to the leaked-query transaction tracked
  in [duckdb/duckdb#25876](https://github.com/duckdb/duckdb/issues/25876); it does not weaken a
  refusal, it changes the error the following statement reports.

Reading `enforced` and `warnings` together in projections and filters is supported on both engines.
Use the standalone `CALL gatekeeper_enforce()` for activation. An arbitrary SELECT wrapper
can eliminate the table function entirely: `LIMIT 0`, `WHERE false`, or an unused subquery
can return successfully without latching on either engine. If setup uses a SELECT projection,
require the actual returned `enforced = true` row; an empty result is not activation evidence.

Gatekeeper parses with the connection's parser options, so it follows the engine onto DuckDB
1.5's opt-in PEG parser (`LOAD autocomplete; CALL enable_peg_parser()`, the default parser from
2.0), and the Python suite runs under both parsers; decisions agree, and the parsers differ
only in diagnostics (query locations, which stage reports `max_expression_depth`). One
engine property does not carry over: the 1.5.x PEG matcher recurses once per nesting level
with no depth guard and no stack check, so `max_expression_depth`, which is the binder's check
under PEG, never runs on text deep enough to matter. About 1000 nested calls overflow an
8 MiB main-thread stack in the engine's own parse, and about 75 nested calls or 100 nested
subqueries overflow a 512 KiB worker-thread stack (the macOS default), which is where
`gatekeeper_validate(?)` parses when its pipeline runs on a worker. The process dies before
Gatekeeper's own depth limit sees the statement. Upstream fixed this on `main` by moving the
matcher's recursion to the heap ([duckdb#24618](https://github.com/duckdb/duckdb/issues/24618),
[duckdb#25204](https://github.com/duckdb/duckdb/pull/25204)); no 1.5.x release carries the fix.
On 1.5.6, do not enable the PEG override on a database that takes untrusted SQL text.
The local tests and randomized-input checks are not a complete security audit.
DuckDB builds and signs the binaries it distributes through its community repository.
Local builds, CI artifacts, and this project's GitHub Release binaries are unsigned. Distribution
signatures authenticate the distributed binary, not its policy semantics or suitability for
hostile workloads.
Platform CI, browser tests, and fuzzing provide regression coverage; production use
against hostile callers still requires review of the application and its trust boundary.
Suspected authorization bypasses should be reported privately as described in
[SECURITY.md](../SECURITY.md).

## Adversarial regression coverage

`test_redteam.py` checks nested table references in filters, windows, LIMIT/ORDER BY,
CTEs, views and macros; search-path and temporary-table shadowing; dynamic SQL;
write-containing batches; duplicate typed policy fields; fixed limits; and prepared
validation after catalog/policy changes. `test_global_policy.py` checks locking,
atomic replacement, strict configuration, and non-bypassable policy layers.
`test_adversarial_generated.py` combines nested queries and function
spellings deterministically and checks single-row NULL/allow/deny results and prepared executions.

DuckDB can wrap policy exceptions while binding a table macro. Such denials retain
`forbidden`, and all exception exits explicitly clear `allowed` so successful
preflight cannot leak into an error
result. Tests cover this independently of the error's DuckDB exception type.

Gatekeeper's AST and bound-expression walks use explicit work stacks. The AST walk
checks node and depth budgets. DuckDB parsing/serialization still has its own stack behavior.

The Python-wheel sanitizer runner uses AddressSanitizer and UndefinedBehaviorSanitizer
to instrument Gatekeeper and its compiled JsonSerializer. The Python DuckDB engine
and bundled yyjson library are not sanitizer-instrumented. Leak detection and vptr
checks are disabled for this mixed-runtime setup. This is regression testing,
not coverage-guided fuzzing or a full engine memory-safety audit.
Run `.venv/bin/python scripts/test_sanitized.py` for the instrumented suite.

The linked SQL/typed-option fuzz target exercises the public entry point against
fixed local catalog fixtures on every PR and main push, with an additional weekly run.
Its deterministic startup checks cover native policy setters and reentrant/stateful
replacement callbacks. Gatekeeper uses coverage and ASan/UBSan instrumentation;
the linked DuckDB engine is exercised but not fully instrumented. The macOS
Python-wheel sanitizer runner also disables libc++ container annotations because
containers cross instrumented and uninstrumented code. This is qualified
mixed-runtime coverage, not a whole-engine clean sanitizer bill.
