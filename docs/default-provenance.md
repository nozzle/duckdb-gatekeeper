# Default function identity provenance

`inventories/default_identities.json` translates the **953 historically reviewed compute
names** into **919 explicit identities covering 913 names**, with **40 explicit namespace
exclusions**. There are **zero unresolved names**. Historical classifications, implementation
review notes and `baselines/duckdb-1.5.5.json` remain unchanged.

| Kind | Explicit defaults |
| --- | ---: |
| scalar | 728 |
| aggregate | 83 |
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

- DuckDB 1.5's `internal_window_functions` parser table defines executable window
  intrinsics, represented by Gatekeeper as `system.main` with kind `window`.
  `duckdb_functions.cpp:194-220` constructs temporary reporting entries (OID zero) and
  labels them `aggregate`, with an explicit FIXME that the label should be `window`.
  These are not executable aggregate registrations. No aggregate grants are justified
  by those rows. `first` and `last` have independent real aggregate registrations.
- DuckDB 2.0's window registration inputs explicitly register those thirteen names
  as `window`, including `rank_dense`. The same window-only grants cover both engines;
  runtime reporting never broadens the kind set.
- `unnest` has a registered table identity and a source-defined SELECT-list binder
  intrinsic represented by Gatekeeper as `system.main.unnest` of kind `scalar`.
  Both are explicit. A table registration never implicitly authorizes scalar dispatch.
- `round_even` and its `roundbankers` alias change from historical macros to explicit
  scalar registrations in the pinned 2.0 math registration inputs. Both kinds are recorded.
- `range`, `generate_series`, and `repeat` each have independently registered scalar
  and table forms. These plus scalar `unnest` and two rounding transitions explain the
  six identities beyond the 913 granted names.

The 13 removed synthetic aggregate grants are `cume_dist`, `dense_rank`, `fill`,
`first_value`, `lag`, `last_value`, `lead`, `nth_value`, `ntile`, `percent_rank`, `rank`,
`rank_dense`, and `row_number`. All retain window grants. A native aggregate registered
under any of these names needs its own explicit grant.

## Runtime cross-check and limitations

The historical Python snapshot cross-checks kinds for names it contains. Its loaded
extensions are core_functions, ICU, JSON and Parquet. It has no catalog/schema fields;
none are retroactively invented. ICU locale scalar names remain an explicit historical
list: source determines the `icu_collate_` naming/kind registration, and the historical
snapshot cross-checks the reviewed locale entries. New runtime locales grant nothing.
The map's version-specific `reporting_discrepancies` explicitly records all 13 historical
aggregate/window mismatches. Audit reports show those explanations alongside unchanged
raw labels. A matching name/label is not proof of intrinsic provenance: qualified aggregate
rows still appear as ungranted identities, so a native collision cannot be hidden by this
explanation. The historical snapshot is never rewritten to make the kinds match.

Autocomplete, Delta, DuckLake, Excel, FTS, Iceberg, INET, PostgreSQL, Quack, Spatial,
TPC-DS and TPC-H have registration-source evidence even though absent from that
historical snapshot. The evidence groups retain that original coverage limitation;
new qualified observations are checked in separately under `inventories/runtime/`:

- [DuckDB 1.5.5, macOS ARM64](../inventories/runtime/duckdb-1.5.5-osx_arm64/README.md):
  locked replay succeeded for 28 of 29 extension setups, including the extensions above.
  MotherDuck was installed but deliberately not loaded. The independent captures observe
  903 of 919 default identities. The 16 unobserved identities are the 13 window intrinsics
  reported as aggregates, the two 2.0-only rounding scalars, and scalar `unnest` (a binder
  intrinsic). No target-added default-name identity falls outside the grants; the aggregate
  report still flags the 13 synthetic window labels. `vortex_version` is the only added
  name absent from the historical classifications.
- [DuckDB 2.0 candidate, macOS ARM64](../inventories/runtime/duckdb-2.0-d4e72566aa-osx_arm64/README.md):
  locked replay succeeded for 25 of 29 setups at `d4e72566aa`; Lance, MotherDuck, UI and
  Vortex artifacts were unavailable at the recorded coordinates. The independent captures
  observe 913 of 919 default identities, with no default names at ungranted identities.
  The six unobserved defaults are two ICU locale scalars, the two historical rounding
  macros, Spatial's `st_snap`, and scalar `unnest`; the candidate report links their
  source reconciliation. Its 248 unclassified runtime names grant no permissions.

These collections preserve shared qualified bases, per-extension dependency/target deltas,
artifact locks and stage hashes. Their aggregate reports are unions of independent setups,
not a single combined live catalog or proof of individual function ownership. They are
runtime observations, **not accepted extension baselines**, replacements for the historical
baseline, or new implementation reviews. Source-backed grants and classifications remain
unchanged. Extensions with no compute names contribute no defaults; binary-only MotherDuck
continues to contribute none. No source-limited name was silently dropped.

New captures retain catalog, kind and full schema paths. On engines exposing nested
schemas, ancestry is reconstructed by schema OID; dependency edges disambiguate same-leaf
schemas for functions. Literal dots stay inside a single identifier component. Ambiguous
or missing provenance fails capture instead of flattening or guessing a path.

Audits report qualified additions/removals only between qualified snapshots, flag reviewed
default names registered at ungranted identities, and list defaults not observed. A missing
optional extension or a kind belonging to the other engine version is not a reason to
remove a grant. Candidate captures and reports never modify the map or historical baseline.
