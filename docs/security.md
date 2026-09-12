# Security model

Gatekeeper phase one is a pre-execution validator, not an enforcement hook or a
database sandbox. A successful decision means the SQL conforms to the selected
syntax and resolved-object policy on the pinned parser/binder. It does not mean the SQL is cheap,
returns nonsensitive data, or cannot have side effects through admitted functions.

## Integrating

1. Load a trusted extension build and keep the execution catalog/search path trusted.
2. Construct policy from authenticated application context. Do not allow an untrusted
   caller to replace deployment restrictions with weaker options.
3. Call `gatekeeper_validate` with the exact SQL to execute.
4. Require an explicit successful result; reject missing results, NULLs, and exceptions.
5. Execute the same SQL under controlled database/process settings.

`gatekeeper_configure` installs database-scoped defaults once. Request overrides
replace values and may relax restrictions; these defaults are not a security
baseline. Only trusted bootstrap should configure the instance. Request state is
local to each scalar call. All effective restrictions intersect and blocks win.

## Remaining boundaries

- Validation always binds on the calling connection and authorizes retrieved table
  and view identities, including underlying objects from views/macros. No public
  syntax-only mode exists. Function policies do not verify which macro/UDF implements
  a name; catalog integrity is assumed.
- Trusted catalog code and attached tables may invoke elevated readers internally.
  Backing-file reads for an authorized logical table are allowed. Binder callbacks
  identify tables without depending on a particular scan operator. Local Iceberg
  REST/MinIO and DuckLake integration tests verify this boundary; other catalog
  implementations still need verification.
- Binding may perform remote I/O or evaluate bind-time expressions before returning,
  even for a request eventually denied. Caller-authored prohibited functions are
  rejected first; trusted expansions are not rechecked against function policy.
- No row/column authorization or execution-time memory/time/result limits.
- Default functions are a reviewed name inventory, not a proof of harmlessness for
  every overload, argument, or future version.
- File-reference detection is conservative and incomplete. Binder-collected
  host-language and implicit replacement scans are rejected as unsupported; explicit
  admitted readers and trusted catalog objects are the supported access paths.
- Direct readers are controlled by function policy. There is no reader-argument
  inventory or local/remote path policy; admitting a reader permits its resource
  access. Resolved bindings do not provide an argument-level sandbox.
- Explicitly admitting dynamic SQL or elevated readers transfers responsibility
  for their hidden dependencies to the application.
- AST validation occurs after parsing and serialization; traversal limits do not
  replace process limits against parser/serializer resource exhaustion.

Keep external access, extension loading, credentials, filesystem/network permissions,
and configuration changes controlled independently. A future locked connection
enforcement mode needs separate analysis of binding-time side effects and prepared
statement lifecycle.

## Compatibility and review

Only the pinned DuckDB 1.5.5 revision is supported. Internal C++ and serializer APIs
require rebuilding/reviewing for other versions. Unknown serialized fields and
node classes fail closed; opaque values are not interpreted as executable nodes.
The local tests and randomized-input checks are not a complete security audit.
Distribution signing, broader platform testing, fuzzing, and production review
remain required before deployment against hostile callers.

## Adversarial regression coverage

`test_redteam.py` checks nested table references in filters, windows, LIMIT/ORDER BY,
CTEs, views and macros; search-path and temporary-table shadowing; dynamic SQL;
write-containing batches; duplicate/escaped JSON keys; invalid limits; and prepared
validation after catalog/default changes. Policy opt-outs are verified to be
request-local. `test_adversarial_generated.py` combines nested queries and function
spellings deterministically and checks mixed NULL/allow/deny vectorized results.

A confirmed issue was fixed during this review: DuckDB can wrap policy exceptions
while binding a table macro. Such denials now retain `forbidden`, and all exception
exits explicitly clear `allowed` so successful preflight cannot leak into an error
result. Tests cover this independently of the error's DuckDB exception type.

A repeat mixed-runtime sanitizer run crashed during deep-nesting coverage after
an earlier pass. Gatekeeper's recursive walk was replaced by an explicit work
stack, preserving per-node scope snapshots and depth checks. Release tests and two
subsequent full sanitizer runs passed; the exact cause of the earlier crash was
not established. DuckDB parsing/serialization still has its own stack behavior.

The full 223-test suite passed with AddressSanitizer and UndefinedBehaviorSanitizer
instrumenting Gatekeeper and its compiled JsonSerializer on macOS arm64. The Python
DuckDB engine and bundled yyjson library were not sanitizer-instrumented. Leak
detection and vptr checks were disabled for this mixed-runtime setup. This is
regression testing, not coverage-guided fuzzing or a full engine memory-safety audit.
Run `.venv/bin/python scripts/test_sanitized.py` to reproduce the instrumented suite.

The linked SQL/typed-option fuzz target exercises the public entry point against
fixed local catalog fixtures. Gatekeeper uses coverage and ASan/UBSan instrumentation;
the linked DuckDB engine is exercised but not fully instrumented. The macOS
Python-wheel sanitizer runner also disables libc++ container annotations because
containers cross instrumented and uninstrumented code. This is qualified
mixed-runtime coverage, not a whole-engine clean sanitizer bill. Earlier counts
above describe historical runs rather than the current test count.
