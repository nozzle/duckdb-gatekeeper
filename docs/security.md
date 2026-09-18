# Security model

Gatekeeper decides whether one SQL statement conforms to the selected syntax, caller-function
and resolved-deny/object policies on the pinned parser/binder. It offers that decision two ways:
`gatekeeper_validate` returns it to the host before the host executes, and an
[enforced connection](#enforced-connections) makes DuckDB refuse to execute anything the
decision denies. Neither means the SQL is cheap, returns nonsensitive data, or cannot have side
effects through admitted functions. Gatekeeper is a statement-level sandbox, not an
operating-system, memory, or network sandbox.

## Integrating

Preferred: hand untrusted callers an enforced connection and execute their SQL on it directly.

1. Load a trusted extension build and keep the execution catalog/search path trusted.
   Provision required extensions and attach catalogs first, then set
   `autoload_known_extensions=false` and `autoinstall_known_extensions=false`, and
   `enable_external_access=false` where the deployment allows. Gatekeeper does not
   mutate those settings; `CALL gatekeeper_enforce()` reports them in `warnings`.
2. Install the global policy through trusted `CALL gatekeeper_configure`. To observe a policy
   against real traffic before it refuses anything, `SET gatekeeper_log_only=true` ([log-only
   mode](#log-only-mode)). Then `SET lock_configuration=true`, which freezes both.
3. `CALL enable_logging('Gatekeeper')` so denials are [recorded](#audit-log); choose a
   storage the sandboxed connections cannot reach in-process (`storage := 'file'` or
   `'stdout'`) when no host connection will remain to read the in-memory log.
4. Run `CALL gatekeeper_enforce()` on each connection you hand out. Enforcement is per
   connection and there is no instance-wide switch; put the call where connections are
   created so no code path can skip it.
5. Execute the caller's SQL on that connection. A denial raises `Permission Error:
   Gatekeeper denied this statement ...` and executes nothing.

Validate-first, for hosts that cannot dedicate a connection:

1. Steps 1 and 2 above. Construct any further request restrictions from authenticated context.
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
`catalog`, `schema`, or leaf) fails closed instead of widening catalog matching.
See [global policy](../README.md#global-policy) in the README.

Validation returns one row with `allowed`, `code`, `violations`, `error_type`,
`error_message`, `position`, `objects`, and `functions` as named columns. Require
`allowed = true` and `code = 'ok'`. The diagnostic/dependency lists retain nested
STRUCT elements. SQL text and options accept constant expressions or host-bound
parameters, not correlated/lateral per-row expressions. For multiple SQL strings,
make separate parameterized calls. Prepared executions read the current policy and
bind the submitted SQL again; preparing a call does not cache an authorization decision.
Validation also rejects non-null placeholder plans with unresolved parameter types;
otherwise execution could rebind to an implementation the validator never authorized.

Use `SELECT allowed FROM gatekeeper_validate(...)` to select an individual column,
or select `*` for all result columns.
Empty option lists are accepted regardless of element type, since DuckDB resolves
untyped `[]` to `INTEGER[]` before table binding. All-NULL lists also pass the element-type
check regardless of declared type (`[NULL]` and `[NULL]::DOUBLE[]` both return `invalid_input`
at execution). Lists with non-NULL members require the documented element types.
Nested identity fields are preserved
and checked, including the field names of typed empty STRUCT lists.

Tables and views are unrestricted until a layer configures `allowed_tables`; only
internal objects (`duckdb_*`, `information_schema.*`) need an explicit rule from the
start. Set `allowed_tables` in the global policy during trusted setup when tenants must
not see every table; `[]` denies all tables and views.
`allowed_tables` is a union of catalog/schema/table rules within each layer, with
an intersection between layers. A whole-component `*` matches any identifier;
other text is exact and ASCII case-folded. Matching uses resolved identities, not
caller spellings or CTE names. Wildcards cover future objects as well as existing
ones. `blocked_tables` uses the same matching rules, defaults to no blocks, and
works independently of the allowlist. A matching block in either layer always wins,
including on underlying tables/views introduced by trusted views and macros.
Blocks match resolved objects, not CTE names or reader paths/arguments.
Internal objects require exact schema/table names in a matching allow rule; a
wildcard catalog is permitted. Block wildcards also match internal objects, even
when an exact allow rule exists. Metadata readers remain independently forbidden,
and schema-wide `SHOW` is denied under any configured table restriction.
Table rules do not restrict or authorize function/type namespaces. Functions use
leaf-name policies; types are supplied by the host without separate authorization;
see [table ACL](../README.md#table-acl).

## Enforced connections

### Threat model

The caller can submit arbitrary SQL text to an enforced connection and observe results and
error messages. The host process, its code, the objects it created (views, macros, attached
catalogs), and the connections it did not enforce are trusted. Host-language APIs on the
connection object itself (Python's `DuckDBPyConnection` methods other than executing SQL,
the C++ `Connection`) are out of scope: a caller holding them can open a new, unenforced
connection. Hand out the ability to execute SQL, not the object.

### Two boundaries

Gatekeeper decides at two points in DuckDB's query lifecycle. Each owns a guarantee that can
be stated and tested independently.

**Binding boundary** (`ClientContextState::QueryBegin`, before the engine binds). The
statement text is parsed with the connection's parser options, serialized, and walked
against the compiled grammar and the global policy exactly as `gatekeeper_validate` does.
When the statement has no parameters, it is then bound privately with the catalog-lookup
callback and replacement-scan interception, so every retrieved table and view, including
those a view or macro expands to, is authorized by resolved identity. Guarantee: no SQL text
submitted for execution reaches the engine's binder unless it is a single `SELECT` whose
grammar, caller-written functions and (parameter-free) resolved objects the policy allows, or
the one statement DuckDB's own parser derives from such a `SELECT`: the temporary enum type of
a dynamic `PIVOT` (below), admitted by exact shape and checked as the `SELECT` that defines it.
Consequently an agent-written `read_csv('s3://...')`, `FROM 'file'`, or `duckdb_settings()`
never opens a file, socket, or metadata reader, and DDL/DML/`SET`/`LOAD`/`ATTACH`/`COPY`
never reach the binder.

**Execution boundary** (`PlannerExtension::post_bind_function`, after the engine binds and
before it optimizes or executes). The plan the engine produced must contain only reviewed
read-only logical operators, modify no database, return a query result, scan only base
tables the policy allows (each `LOGICAL_GET` table entry is authorized by resolved identity),
and pass the same resolved-function and implementation checks `gatekeeper_validate` applies
to its own plan. The one other root it accepts is a dynamic `PIVOT`'s enum type
(`LOGICAL_CREATE_TYPE` of that exact shape, in the temporary catalog, returning nothing) over
such a plan. If the binding boundary deferred object authorization because the statement
had parameters, it runs here with the values the engine bound them to. Guarantee: no plan
executes on an enforced connection unless it consists of allowlisted operators over allowed
base tables and functions. This holds for every plan the engine's planner produces, whatever
produced the statement: SQL text, a prepared statement, or DuckDB's relation API. Views are
inlined before this point; they are authorized by the private bind's catalog callback, which
for a relation statement sees the relation's SQL rendering rather than its query node.

Both boundaries read one policy snapshot per statement. DuckDB's `Prepare()` path binds
before any extension hook runs, so on that path the execution boundary only pre-screens the
prepared plan; at execution, `OnExecutePrepared` forces a rebind inside the query so the plan
that runs is authorized under the current policy, and a cached plan can never outlive a policy
change. Together the two boundaries make enforcement agree with `gatekeeper_validate` on every
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

  There is no interception point in front of it in DuckDB 1.5.5: `TransactionBegin` fires
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
- **`Prepare()` before hooks.** DuckDB binds a prepared statement before any extension hook
  runs. Agent-written readers are still denied before execution, but the bind of a statement
  that will be denied has already happened; with external access enabled, that bind can
  perform reader I/O whose only observable effect for the caller is the denial's timing.
  The replacement-scan gate does run during that bind, with no statement text on record, so
  it holds every substituted reader to the allowlist there: a caller's `FROM 'file'` is
  refused before anything opens, and so is a trusted view that names its file the same way.
  Such a view cannot be prepared on an enforced connection unless its reader is allowed;
  executing the statement directly (with or without parameters) binds inside the query,
  where the text is on record, and a view written with an explicit `read_parquet(...)` call
  is unaffected either way. The plan pre-screen after that bind has no record either, so it
  applies table policy and the never-bind list and defers `blocked_functions` to execution:
  a prepared statement whose text names a blocked function is refused when executed, not
  when prepared.
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
  text. Treat all of them as sensitive when relaying to untrusted callers or storing the log.
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
never-bind list so validated SQL cannot name it either.

There is deliberately no instance-wide setting. One would have to choose between enforcing the
host's own connections (leaving no in-process reader for the audit log and no way to change
the policy) and depending on connection-open ordering, and a setting is one more thing a
trusted connection can be talked into flipping. A connection is enforced because the host said
so on that connection, at that moment.

### Log-only mode

`SET gatekeeper_log_only = true` is a global BOOLEAN setting, default `false`, reversible, and
frozen by `lock_configuration`. While it is true, every enforced connection makes and records
every decision exactly as it otherwise would, and refuses nothing: a denial is written to the
log with `mode = 'log_only'` and the engine then binds and executes the statement as it would
on an unenforced connection. It exists so a policy can be measured against real traffic (what
would be refused, and what the traffic resolves to) before any of it is refused.

Semantics that follow from "the same decision, without the refusal":

- The switch is read once per statement, in `QueryBegin` next to the policy, and snapshotted
  with it, so every boundary of one statement agrees; a flip applies at the next statement on
  every enforced connection, in both directions.
- Identical checks at identical cost: the text check, the private authorizing bind, the
  rebind of prepared executions, and the plan check all run. What log-only measures, denials
  and latency alike, is what enforcement will do.
- Exactly one record per statement, at the boundary that decided it, in both modes. Once a
  log-only statement has been decided, the hooks the engine reaches while binding and
  executing it anyway do not decide it again. The replacement-scan gate lets the engine's own
  bind through for a statement already decided; for one not yet decided (parameters defer
  authorization to the engine's bind, and a `Prepare()` has no statement in progress) the gate
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
- A `Prepare()` outside any query is pre-screened as before and a denial there is recorded
  with `mode = 'log_only'`; each later execution is its own record.
- **Log-only mode protects nothing, including Gatekeeper.** On a log-only connection `SET
  gatekeeper_policy`, `CALL gatekeeper_configure()`, and `SET gatekeeper_log_only` are
  unsupported statements that are recorded and then execute, exactly like every other
  statement. The connection stays enforced, so flipping the switch back restores refusals on
  it, but until then the caller has the whole engine. `lock_configuration` is the mitigation,
  as for the policy; the `lock_configuration` posture warning names both settings, and
  `gatekeeper_enforce()` warns whenever the switch is on.
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
`code`, `violations`, `error_type`, `error_message`, `position`, `objects`, `functions`), so the
log and the function describe a statement the same way; `test/test_audit.py` asserts this over
the enforcement parity corpus. The rest of the record is:

| column | meaning |
| --- | --- |
| `event` | `decision`, `policy_changed`, or `log_only_changed` |
| `mode` | `enforce` (an enforced connection), `log_only` (an enforced connection while `gatekeeper_log_only` is true; the statement ran regardless), or `validate` (`gatekeeper_validate`) |
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
  is the text check's own rejection (its limits, multi-statement text) or a policy the host left
  unreadable through a native write, and `parser` is Gatekeeper's own parse failing on text the
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
treated as functions. `->>` and JSON path aliases share canonical extraction blocks.

Function allowlisting cannot be disabled. Each policy layer admits its explicit
`allowed_functions` plus the reviewed defaults when `use_default_functions` is true;
explicit blocks and the never-bind list take precedence for what the caller writes.

The Parquet reader names `read_parquet` and `parquet_scan` share allow/block
permission. This explicit pair is source-reviewed in
`duckdb/extension/parquet/parquet_extension.cpp` (`LoadInternal` registers the same
`ParquetScanFunction::GetFunctionSet()` under both names). There is no dynamic alias
discovery. CSV/JSON reader names are not grouped. Parquet violations use the canonical
name `read_parquet`; successful dependency lists retain observed function names.

**Trusted definitions are opaque to function policy.** A view, scalar macro, or table
macro the host created (any non-internal catalog entry), and the scan an attached catalog
uses for a table the policy allows, are trusted definitions. What their bodies introduce is
theirs, not the caller's: an explicit `read_parquet(...)`, a file path (`FROM 'x.parquet'`),
`md5`, `list_sum` and the `sum` it dispatches, the `lower` behind a `COLLATE nocase`,
`iceberg_scan`. None of it is subject to the allowlist or to `blocked_functions`. Only the
non-overridable never-bind list below reaches inside a body, and table policy still
governs the view or table itself (and every table the body reads), while a macro must
itself be allowed by name. Blocks govern what is attributable to the caller: the names in
the caller's text, the names the caller's own binders retrieve while binding it (the
default macros a caller-written name expands to, such as `list_sum` to `list_aggr`), the
aggregate a caller-attributable dispatcher selects, and the collation functions when the
caller wrote `COLLATE`. The exemption is by origin, not by name: the same function
written by the caller next to a view that also uses it is the caller's, and the caller's
rules then apply query-wide, since the bound plan carries no scope.

Origin is established during the private bind. DuckDB copies a binder's catalog-lookup
callback into every child binder it creates and creates the binder for a view or table
macro body right after retrieving that entry, so Gatekeeper's callback carries scope:
retrieving a host view or table macro arms the copy that made the lookup, the next copy
made from it (the body's binder) starts trusted, and trusted copies beget trusted copies.
Lookups a trusted copy makes are the definition's own. A scalar macro body binds in the
caller's own binder, so its names are learned from its definition: the macro's expression
is walked by the same grammar walker as the caller's text, and a name it introduces that
the caller did not also write is the macro's. The execution boundary then applies blocks
only to names the record attributes to the caller; an attached table's scan
(`LogicalGet` with a table entry) is never attributed. A `Prepare()` bind outside any
statement has no text and no record; its pre-screen applies table policy and the
never-bind list and defers blocks to execution, which rebinds inside the query.

The callback exposes no expression origin within one binder: when caller syntax requires
an implementation check, a trusted expansion using the same implementation must also pass
it. This conservative query-wide restriction can deny a mixed caller/view expression; it
does not grant an exception to caller code. Type names, casts, and collations are trusted
host database configuration and are not authorized separately. Trust covers the whole
body, arguments included: a host macro that forwards a caller argument into a reader
(`CREATE MACRO files(p) AS TABLE SELECT * FROM read_parquet(p)`) hands the caller that
choice, and neither the allowlist nor `blocked_functions` stands in the way. Do not create
pass-through definitions for capabilities the policy is meant to withhold; DuckDB itself
refuses a macro that forwards an aggregate name into a dispatcher, since the name must be
a constant.
Name-selected aggregate dispatch (`list_aggregate`, `list_aggr`, `aggregate`,
`array_aggregate`, `array_aggr`) is elevated, and admitting a dispatcher does not admit
every aggregate it can reach: when the caller writes one, the aggregate DuckDB resolves
from the caller's (foldable) name argument must pass both allowlists, and like other
ambiguous caller syntax the check applies query-wide, so a trusted view's own dispatch in
the same plan is checked too. Dispatchers used only inside trusted definitions, and the
fixed `histogram` behind `list_distinct`/`list_unique`, are those definitions' own.

Defaults are admitted by leaf name, so a host-created macro or function that shadows a
default name is a trusted definition: `CREATE MACRO ltrim(x) AS ...` in a schema ahead of
`system` on the search path is admitted whenever `ltrim` is, and its body is checked
against the never-bind list only. The same holds for views, types, casts, and
collations. Gatekeeper assumes catalog integrity; letting untrusted users create
definitions in a shared catalog is outside its model, and restricting defaults to
`system.main` would not by itself make such DDL safe.
Concretely, with defaults disabled, `SELECT * FROM v_st` may pass but
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
query query_table json_execute_serialized_sql json_serialize_plan read_duckdb seq_scan which_secret
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
Metadata views expanding to these readers are denied even with `allowed_tables`.
This is deliberate: metadata readers enumerate across catalogs and cannot be row-
filtered by object callbacks. Tenant introspection must use a host-controlled API.
`json_serialize_plan` is listed because it binds and plans caller-supplied SQL at
execution time, outside this validation.

### Callback bypasses

Gatekeeper does not restrict type or collation names, or authorize cast implementations.
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
catalogs/schemas fail closed before their serialization callbacks can run.
`list_distinct`/`list_unique` and their `array_*` aliases use the source-reviewed fixed
`histogram` implementation.
These implementations obey blocks in both layers and appear in successful function
evidence. Their catalog/schema are empty when the bound representation supplies no
reliable provenance. Arbitrary extension bind data is not introspected.

## Remaining boundaries

- Validation always binds on the calling connection and authorizes retrieved table
  and view identities, including underlying objects from views/macros. No public
  syntax-only mode exists. Function matching remains name-based, not a proof of a
  macro/UDF's implementation; catalog integrity is assumed.
- Trusted catalog code and attached tables may invoke elevated readers internally.
  Backing-file reads for an authorized logical table are allowed. Binder callbacks
  identify tables without depending on a particular scan operator. Local Iceberg
  REST/MinIO and DuckLake integration tests verify this boundary; other catalog
  implementations still need verification.
- Binding may perform remote I/O or evaluate bind-time expressions before returning,
  even for a request eventually denied. Caller-authored prohibited functions are
  rejected first; trusted expansions are outside function policy and pass the
  never-bind list only. Lookup-triggered autoload can occur before the callback; use
  the host settings above, even for names included in the default inventories.
- No row/column authorization or execution-time memory/time/result limits.
- Default functions are a reviewed name inventory, not a proof of harmlessness for
  every overload or argument. Existing DuckDB implementations are trusted across
  engine upgrades; the inventory is not an exact-version compatibility gate. New
  names remain excluded until classified or explicitly allowed. The inventory admits the clock (`now`,
  `current_date`, `uuidv7`), non-cryptographic PRNG state including `setseed`'s reseed of
  the connection-local engine, and the host's `TimeZone`/`Calendar` settings that ICU
  temporal functions consume; results using them are not reproducible from SQL text
  alone, and a host that caches or replays tenant queries must account for that. All
  other catalog, session, configuration, or planner state is opt-in; see
  [inventories/README.md](../inventories/README.md#classification-criteria).
- Replacement scans are decided by a Gatekeeper callback installed first in DuckDB's
  replacement-scan list. It runs while a validation is binding on the calling thread
  and on every enforced connection; ordinary connections are unaffected. Other callbacks only construct a table
  reference, so a denial happens before the substituted reader binds and no file is
  opened. Readers substituted by DuckDB are authorized by their resolved names
  (`parquet_scan`, `read_csv_auto`, `read_json_auto`), with `parquet_scan` sharing
  permission with `read_parquet`. No separate replacement-scan toggle exists. The check
  applied depends on who wrote the name: a table name in the caller's text (quoted or not,
  in any clause, including `DESCRIBE`, `PIVOT`, CTEs and subqueries) is the caller's reader
  choice and must pass every allowlist layer; a name reachable only through a view or
  macro body is that trusted definition's reader, outside function policy exactly as an
  explicit `read_parquet(...)` in that body is, and passes the never-bind list only. The
  callback receives only the name, so the text walk records every table name the caller
  wrote and the gate consults that record (the private bind's, or the admitted statement's
  on an enforced connection); a name both sides use is checked as the caller's. A
  `Prepare()` bind outside any statement has no text on record and is pre-screened as
  though the caller wrote every name; `OnExecutePrepared` then rebinds inside the query,
  where the record exists.
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
  list cannot be overridden by any option.
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
CALL gatekeeper_configure(allowed_tables := [{catalog: 'memory', schema: 'reporting', 'table': '*'}]);
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
inherit caller CTEs whereas views do not; compare actual resolved objects rather than
assuming definition-time bindings. User-defined enum types can expose all their labels
via `enum_range`, even when no table is read; type definitions are host-trusted data.

## Compatibility and review

Release binaries target DuckDB 1.5.5. Source builds may use another engine checkout;
the grammar and serializer come from that checkout, and DuckDB enforces binary
compatibility through the extension footer. That footer check can be disabled with
`allow_extensions_metadata_mismatch`, so Gatekeeper also records the engine it was built
from (the version tag for releases, the source id for dev builds, mirroring DuckDB's own
footer identity) and refuses to load into any other engine. The stamp is a single string
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
(`compatibility.yml`), through both the direct CMake path and the community `make release`
path. Existing function classifications do not
need repeating for each engine version. Unknown serialized fields and
node classes fail closed. Cast types use latest `UNBOUND(TypeExpression)` decoding,
including nested type parameters. Computed type parameters remain conservatively
unsupported. Ordinary literal payloads remain data, not executable nodes.
The local tests and randomized-input checks are not a complete security audit.
DuckDB builds and signs binaries distributed through its community repository;
Gatekeeper's community publication is pending. Local builds, CI artifacts, and this
project's GitHub Release binaries are unsigned. Distribution signatures authenticate
the distributed binary, not its policy semantics or suitability for hostile workloads.
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
