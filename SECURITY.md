# Security policy

Gatekeeper authorizes untrusted SQL before it runs. Bugs that let a validated statement do
something the documented policy prohibits are security vulnerabilities and are handled
privately until a fix is released.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/nozzle/duckdb-gatekeeper/security/advisories/new)
for this repository. Do not open a public issue or pull request for a suspected bypass.

Include the DuckDB version (`PRAGMA version`), the Gatekeeper version
(`SELECT extension_version FROM duckdb_extensions() WHERE extension_name = 'gatekeeper'`),
the global policy and request options in effect, the trusted catalog definitions the
report relies on, the SQL submitted, and the `gatekeeper_validate` result row.

We acknowledge reports within five business days and aim to publish a fix and an advisory
within 90 days of confirmation, sooner for bypasses that need no unusual host
configuration. Please allow us to coordinate disclosure with the DuckDB community
extension repository, which builds and signs the distributed binaries.

## Supported versions

Only the latest tagged release receives fixes. Community-repository rebuilds of that
release for newer DuckDB engines are covered as long as the source revision is the
supported one.

## Scope

In scope: `gatekeeper_validate` returns `allowed = true` and `code = 'ok'` for a statement
that, under the documented policy semantics and the documented integration assumptions
in [docs/security.md](docs/security.md), reads a table or view outside `allowed_tables`
or matching `blocked_tables`; binds a caller-written function outside the allowlists or
matching `blocked_functions`; reaches a never-bind function by any route; is not a single
`SELECT`; or executes, writes, or performs I/O the validator claims it does not. Also in
scope: `gatekeeper_configure` or `SET gatekeeper_policy` widening the policy from a
connection that should not be able to, and a distributed artifact loading into an engine
it was not built for.

Out of scope, by design and documented in
[Remaining boundaries](docs/security.md#remaining-boundaries): row- or column-level
filtering; execution-time memory, time, or result limits; parser or binder resource
exhaustion; I/O that trusted catalogs, views, macros, or explicitly admitted readers
perform during binding; behavior of host-created definitions that shadow default names
or otherwise rely on an untrusted party having DDL in the shared catalog; the contents
of engine `error_message` text; and hosts that leave `autoload_known_extensions`,
`autoinstall_known_extensions`, or configuration changes enabled on validating
connections. Reports in these areas are welcome as ordinary issues.

Vulnerabilities in DuckDB itself should be reported to the
[DuckDB project](https://github.com/duckdb/duckdb/security/policy).
