# Migrating policy inputs to v2

Legacy shapes are rejected, never converted implicitly. Update both allow and block
rules in typed `gatekeeper_validate` / `gatekeeper_configure` calls and JSON policies
(`"version": 2`).

0.3.0 shipped JSON v1. Set `version` to `2` and, if `$schema` is present, use
`https://raw.githubusercontent.com/nozzle/duckdb-gatekeeper/main/docs/policy-v2.schema.json`.
Typed and JSON legacy-rule diagnostics identify the affected option, its replacement rule
shape, and the requirement for a nonempty list of schema components. They do not convert rules.

| Old entry | Replacement |
| --- | --- |
| Function string `"abs"` | `{"catalog":"system","schema_path":["main"],"name":"abs"}` |
| Function `{"schema":"x","name":"abs"}` | `{"schema_path":["x"],"name":"abs"}` |
| Table `{"schema":"x","table":"y"}` | `{"schema_path":["x"],"table":"y"}` |

Choose the intended catalog and full schema path when replacing a bare function
name. `schema_path` is a nonempty list: `["finance", "reports"]` is a nested
schema, while `["finance.reports"]` is one literal schema name containing a dot.
Remove `schema` even when `schema_path` is already present.

Function rules have shape `{catalog?, schema_path, name, type?}`; table rules have
shape `{catalog?, schema_path, table}`. Omitted or NULL `catalog` means any catalog.
Omitted or NULL function `type` means any supported kind. Function `name` is
required and literal: `"*"` names multiplication, not a wildcard. Schema-wide
function grants are unsupported. See [qualified functions](qualified-functions.md)
for matching and authorization semantics and the [JSON schema](policy-v2.schema.json)
for supported kinds.

Configurable grants and blocks match exact catalog-entry names, without alias canonicalization.
Cover each intended Parquet reader (`read_parquet`, `parquet_scan`), JSON extraction entry
(`json_extract`, `json_extract_path`, `->`, `json_extract_string`, `json_extract_path_text`, `->>`),
and window entry (`rank_dense`, `dense_rank`, `first`, `first_value`, `last`, `last_value`)
explicitly. Parquet file shorthand selects `parquet_scan`. Source-defined parser/binder rewriting
determines the parsed operation or selected entry; it does not make policy names interchangeable.

Internal table/view grants require exact schema components and an exact table name; internal
function grants require exact schema components and the always-required exact function name.
Catalog may still be omitted, NULL, or `*`. Block namespace wildcards still match internal entries.
The actual entry's `internal` flag controls this restriction, not the `system` catalog name;
non-internal entries can use schema-pattern grants. Unknown bound-function internal origin cannot
use a schema-wildcard grant. Reviewed defaults already name exact identities.

An empty typed legacy function list (`[]::VARCHAR[]`) or a typed struct list with a
`schema` field still requires migration. Use `[]` or an empty list with the v2
struct type.

Use `gatekeeper_configure` for authoring policies. Direct `SET gatekeeper_policy`
accepts the complete canonical setting: DuckDB casts it before Gatekeeper can
inspect it, so a legacy field may instead be reported as a NULL canonical field.
Canonical catalog/type wildcards use empty strings, not NULL; round-trip the value
returned by `current_setting('gatekeeper_policy')` when using `SET`.
