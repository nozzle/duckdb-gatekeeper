# Named-parameter fallback: conservative delivery of #107

## Decision

Ship a validation preflight and a fail-closed enforced collision gate without changing engine pins.
This is a restricted implementation of [#107](https://github.com/nozzle/duckdb-gatekeeper/issues/107),
not completion of its explicit-value-precedence contract on enforced DuckDB 2.0 connections.

Validation has known inputs (currently none for the SQL being validated). Its preflight checks actual
caller parameter references, skips known supplied entries, and authorizes existing variable fallbacks
against both layers as the fixed `system.main.getvariable` capability. No catalog lookup or variable
value is needed to decide permission. Missing variables continue through ordinary complete binding;
typed placeholders may still bind completely, whereas untyped or value-dependent ones fail.

Enforcement has no trustworthy supplied-input provenance before binding. It refuses every caller
named-parameter/variable collision, including present NULLs, explicit values, allowed getvariable,
and client-API prepares. Log-only records the same refusal and continues with native engine behavior.
Use noncolliding names or positional parameters to supply explicit values. Only caller AST references
are gated: host views remain trusted. A caller argument passed into a trusted macro is still caller text.

## Source evidence and unavailable hooks

Reviewed DuckDB 1.5.5 `d8cdaa33fda8df955cc76ef58a280f68f4cd43fa` and 2.0 alpha
`d4e72566aa8dcb35fc727e2a5ced8e9a2f6d8143`:

- `src/planner/binder/expression/bind_parameter_expression.cpp`: 1.5 only reads explicit parameter
  data. 2.0 tries explicit entries first, then `GetUserVariable` outside PREPARE mode. The result is
  a constant, with no catalog callback or bound getvariable function. Direct fallback does not add
  an entry to the binder's parameter data.
- `src/planner/binder/statement/bind_execute.cpp`: `PopulateMissingParameterValues` runs **before**
  `OnRebindPreparedStatement`. The callback and the nested planner receive a merged map.
  `BoundParameterData` has no input-origin marker. Comparing values cannot distinguish equal explicit
  input from a fallback. Treating map membership as supplied provenance would silently allow the bypass.
- `src/main/client_context.cpp`: `QueryBegin(ClientContext&)` precedes verification/planning but
  exposes only current text, not the statement object or `QueryParameters.statement_args`.
- `PlannerExtension` exposes post-bind and SQL-value-function resolution hooks, neither a parameter
  read nor general pre-bind hook. Optimizer callbacks also run too late. A parser override has no inputs.
- Table-function arguments, LIMIT/OFFSET, AT, COLUMNS and PIVOT IN can evaluate before post-bind.
  The 2.0 `TransformSampleCount` rejects nonconstant SAMPLE expressions before binding.

The minimum upstream change is an early query callback exposing the actual statement and original
arguments before verification/planning/default merging. Direct queries would use `statement_args`;
internal EXECUTE statements carry `bound_values`; internal PREPARE could defer fallback policy.
Alternatively a pre-bind callback must expose the original EXECUTE before its defaults are merged.
Keep input provenance separate from effective rebind values and repeat authorization every execution.
No proposed engine hook is assumed to exist by this implementation.

Do not use the general parsed-expression iterator to discover all caller references: the reviewed
engine traversal omits AT and portions of PIVOT. The existing serialized grammar walker collects them.
Do not resolve an unqualified getvariable: host shadowing cannot change the fallback capability.
Qualified-function policy work should route this fixed identity through the same identity matcher.

## Values, trusted bodies and diagnostics

The preflight records capability evidence, never variable contents. It leaves effective values to
DuckDB: replacing direct fallback with `BoundParameterData(Value)` can change literal typing and
overload selection. Private validation remains followed by full plan authorization.

Trusted views can retain `$x` and read the current value. SQL scalar macro bodies with `$x` are rejected
by the reviewed engine. The alpha also exhibited an internal error preparing/executing a view-only
parameter query; this change does not claim to repair that engine path. Internal errors still propagate.

Raw engine binding diagnostics can disclose values (e.g. an invalid COLUMNS regex). Gatekeeper
conservatively suppresses their message details on 2.0 whenever session variables exist, including
unrelated variables, because trusted-body reads lack a hook too. Error classes remain available;
DuckDB's own errors/logs and intentionally returned data are outside this decision-log redaction.

## Deferred value-bearing validation API

A separate `parameters := STRUCT(...)` argument declared ANY is feasible: preserve each field's
Value and LogicalType, accept typed NULL, reject duplicate/excess identifiers, and pass an
`engine::ParameterMap` to Check/Authorize. Numeric field names could represent positional inputs.
It must be separate from policy options/JSON and included in bind-data copy/equality with types.
MAP/LIST homogenize types; JSON is lossy. A names-only list cannot establish complete binding.

Defer that public API until exact typed-value versus client literal-typing semantics are documented
and tested. Without it, value-dependent validation still reports binding failures. This API would
not fix enforced collision provenance and is not a substitute for the upstream hook.

## Verification

`test/test_named_parameters.py` covers both engines, layers, evidence, NULL, positional parameters,
bind-time sites, trusted attribution, changes between validations, redaction, and log-only decisions.
`test/sql/named_parameters.test` carries the portable validation contract. The native prepared probe
retains a handle across host variable/policy changes and counts table-function bind invocations:
denied fallback/collision paths must invoke it zero times. Rebuild and run these on both engines;
source-only checks or runs against an older artifact do not verify the new guards.
