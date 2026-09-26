# Migrating policy inputs to v2

Legacy shapes are rejected, never converted implicitly. Update both allow and block
rules in typed `gatekeeper_validate` / `gatekeeper_configure` calls and JSON policies
(`"version": 2`):

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

An empty typed legacy function list (`[]::VARCHAR[]`) or a typed struct list with a
`schema` field still requires migration. Use `[]` or an empty list with the v2
struct type.

Use `gatekeeper_configure` for authoring policies. Direct `SET gatekeeper_policy`
accepts the complete canonical setting: DuckDB casts it before Gatekeeper can
inspect it, so a legacy field may instead be reported as a NULL canonical field.
Canonical catalog/type wildcards use empty strings, not NULL; round-trip the value
returned by `current_setting('gatekeeper_policy')` when using `SET`.
