# Typed API and mandatory resolution

This breaking change replaces the initial JSON options interface. There is no
compatibility JSON overload and no public syntax-only switch.

| Previous | Current |
| --- | --- |
| `gatekeeper_validate(sql, '{"blocked_functions":["md5"]}')` | `gatekeeper_validate(sql, blocked_functions := ['md5'])` |
| `gatekeeper_configure('{"limits":{"max_statements":2}}')` | `gatekeeper_configure(max_statements := 2)` |
| JSON `limits` object | Independent integer arguments `max_statements`, `max_ast_bytes`, `max_ast_nodes`, `max_ast_depth` |
| `resolve_objects:false` | Removed: binding always runs after preflight passes |
| `violations VARCHAR[]` | Structured violations with rule, message, object/function identifiers, and position |

Lists replace configured lists. Each named limit overrides only that limit.
Explicit empty arrays are distinct from omission. NULL option values are invalid;
an omitted catalog in an `allowed_tables` entry may be NULL to accommodate mixed
DuckDB structs. Parameterized arrays and row-varying option values are supported.

## Object boundaries

Previously a trusted file-backed view could bind without producing a TABLE_ENTRY
callback. Views now require authorization themselves, along with any underlying
physical objects. This is deliberately stricter: an allowed view over a forbidden
table is denied, and a forbidden view over an allowed table is denied. Catalog-
installed implementation functions remain trusted, including storage readers.

Binder replacement scans are collected and rejected: they do not have a reliably
authorizable catalog identity. Host-language relation scans and implicit filename
scans should be replaced by trusted catalog objects or explicit admitted readers.
The syntactic file-reference flag cannot alone authorize an unknown replacement.

Explicit table functions admitted by function policy remain capabilities: generators
need not produce table callbacks; direct readers delegate resource access to the
application. Enabled dynamic table lookup is tested to still enforce retrieved
object identities. Object allowlists are not a filesystem sandbox.

## Fuzz targets

The existing standalone AST target retains a fixed restrictive native policy and
mutates AST JSON, exercising the grammar walker/yyjson. JSON policy parsing has been
removed from the public implementation.

The new linked target exercises `gatekeeper_validate` through DuckDB's SQL API:
SQL parsing, typed named-argument binding, native option conversion, serialization,
AST checks, and catalog binding against fixed local tables/views. It never executes
the submitted query plan or configures untrusted extensions.

```sh
docker build -t gatekeeper-fuzz -f test/fuzz/Dockerfile test/fuzz
docker run --rm -v "$PWD:/work" --entrypoint python3 gatekeeper-fuzz scripts/fuzz_sql.py --seconds 60
```

The linked build needs full DuckDB compilation and is slower than standalone AST
fuzzing. Gatekeeper code uses libFuzzer coverage plus ASan/UBSan; DuckDB library code
is traversed but not fully coverage/sanitizer instrumented. Logs, corpus and crash
artifacts remain in ignored `build/sql-fuzz/`. Semantic tests separately assert deny
decisions for views, dynamic lookup, replacement scans, and malformed API calls.

The macOS Python-wheel sanitizer runner disables libc++ container annotations in
addition to leak/vptr checks: containers cross between an uninstrumented Python
DuckDB wheel and instrumented DuckDB code linked into the extension, which produced
a container-overflow report in `BindContext::CreateColumnReference`. This qualified
mixed-runtime test is not a whole-engine clean sanitizer bill; the Linux linked
fuzzer uses a separately built engine and remains an important independent check.

Local typed-API benchmarks through Python (including binding and STRUCT conversion)
measured roughly 0.21 ms simple, 0.25 ms CTE, and 0.33 ms at 20 levels of nesting
while a Docker compiler workload was active. These are diagnostic measurements,
not a controlled speedup comparison to the earlier JSON API.
