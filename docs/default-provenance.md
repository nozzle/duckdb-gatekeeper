# Default function identity provenance

`inventories/default_identities.json` translates the **953 historically reviewed compute
names** into **932 explicit identities covering 913 names**, with **40 explicit namespace
exclusions**. There are **zero unresolved names**. Historical classifications, implementation
review notes and `baselines/duckdb-1.5.5.json` remain unchanged.

| Kind | Explicit defaults |
| --- | ---: |
| scalar | 728 |
| aggregate | 96 |
| macro | 76 |
| table | 19 |
| window | 13 |

Each grant expands to `{catalog: "system", schema_path: ["main"], name, type}`.
`type` is mandatory. No wildcard matching occurs for these defaults; `*` is the exact
registered scalar multiplication operator. Grouping only avoids repeating shared evidence
and namespace fields. `scripts.inventory.load_default_identities(root)` returns a sorted,
unique list of these objects, ordered by catalog, schema path, name, then type.
`load(root)` continues returning `(entries, sorted_compute_names)` for classification tools.
`scripts/generate.py` embeds `{"defaults": [identity objects]}`.

## Registration evidence

Every group links immutable registration source revisions and identifies the owning
classification inventories. The mapping review inspects registration names, aliases, kinds
and namespaces; it trusts the existing implementation classifications rather than repeating
every implementation review.

Core and in-tree extension evidence uses DuckDB
`d8cdaa33fda8df955cc76ef58a280f68f4cd43fa` (the historical 1.5.5 source). The explicit
2.0 window mapping uses `d4e72566aa8dcb35fc727e2a5ced8e9a2f6d8143`. Out-of-tree
extensions use their existing historical source pins, individually linked in the map.

The namespace registration chain at the historical core revision is:

- [`ExtensionLoader::RegisterFunction`](https://github.com/duckdb/duckdb/blob/d8cdaa33fda8df955cc76ef58a280f68f4cd43fa/src/main/extension/extension_loader.cpp)
  explicitly selects `Catalog::GetSystemCatalog`; scalar, aggregate and table overloads
  construct the corresponding `Create*FunctionInfo`. `RegisterCollation` additionally
  creates the corresponding scalar function.
- [`CreateFunctionInfo`](https://github.com/duckdb/duckdb/blob/d8cdaa33fda8df955cc76ef58a280f68f4cd43fa/src/include/duckdb/parser/parsed_data/create_function_info.hpp)
  supplies the default schema. Core's `RegisterFunctionList` and `BuiltinFunctions`
  use these creation objects. Macro generators preserve their declared schema.
- Spatial's `FunctionBuilder` both registers through `ExtensionLoader` and retrieves
  the resulting entries from `system.DEFAULT_SCHEMA`; macro builders explicitly set
  `DEFAULT_SCHEMA`.

Core `functions.json` inputs and their generated registration tables distinguish scalar
from aggregate, including aliases. Descriptive inventory groups are not used as kind
evidence: for example, `geomean`, `list_sum`, and `json_group_array` are macros despite
their aggregate-shaped use. Delta's `parse_delta_filter_logline` and seven spatial
affine convenience functions are also macros.

All 40 excluded names are explicitly enumerated in the map. They are the compute
`DefaultMacro` registrations whose source schema is `pg_catalog` (for example
`pg_typeof`, `pg_conf_load_time`, and `has_table_privilege`). Their prior name-level
classification remains trusted, but does not justify a fabricated `system.main` identity.

## Intrinsics and supported kind transitions

- DuckDB 1.5's `internal_window_functions` parser table defines the window intrinsics.
  `ExtractWindowFunctionData` attributes them to `system.main`, and the historical
  runtime reports kind `aggregate`. Thirteen names have explicit aggregate identities;
  `first` and `last` already have aggregate registrations.
- DuckDB 2.0's window registration inputs explicitly register those thirteen names
  as `window`, including `rank_dense`. Both reviewed kinds are retained as explicit
  grants; runtime discovery never broadens the kind set.
- `unnest` has a registered table identity and a source-defined SELECT-list binder
  intrinsic represented by Gatekeeper as `system.main.unnest` of kind `scalar`.
  Both are explicit. A table registration never implicitly authorizes scalar dispatch.
- `round_even` and its `roundbankers` alias change from historical macros to explicit
  scalar registrations in the pinned 2.0 math registration inputs. Both kinds are recorded.
- `range`, `generate_series`, and `repeat` each have independently registered scalar
  and table forms. These plus the thirteen windows, scalar `unnest`, and two rounding
  transitions explain the 19 identities beyond the 913 granted names.

## Runtime cross-check and limitations

The historical Python snapshot cross-checks kinds for names it contains. Its loaded
extensions are core_functions, ICU, JSON and Parquet. It has no catalog/schema fields;
none are retroactively invented. ICU locale scalar names remain an explicit historical
list: source determines the `icu_collate_` naming/kind registration, and the historical
snapshot cross-checks the reviewed locale entries. New runtime locales grant nothing.

Autocomplete, Delta, DuckLake, Excel, FTS, Iceberg, INET, PostgreSQL, Quack, Spatial,
TPC-DS and TPC-H have registration-source evidence even though absent from that
snapshot. Their identities are retained, with that limitation recorded in each evidence
group. Extensions with no compute names contribute no defaults; binary-only MotherDuck
continues to contribute none. No source-limited name was silently dropped.

New captures retain catalog, kind and full schema paths. On engines exposing nested
schemas, ancestry is reconstructed by schema OID; dependency edges disambiguate same-leaf
schemas for functions. Literal dots stay inside a single identifier component. Ambiguous
or missing provenance fails capture instead of flattening or guessing a path.

Audits report qualified additions/removals only between qualified snapshots, flag reviewed
default names registered at ungranted identities, and list defaults not observed. A missing
optional extension or a kind belonging to the other engine version is not a reason to
remove a grant. Candidate captures and reports never modify the map or historical baseline.
