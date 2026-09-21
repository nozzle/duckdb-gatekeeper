#pragma once
#include "validator.hpp"

namespace duckdb {
class CatalogEntry;
class LogicalOperator;
enum class CatalogType : uint8_t;
// The kind a function entry is reported as in Result::functions (scalar, aggregate, table, macro, table_macro,
// pragma), or null for every catalog entry that is not a function.
const char *FunctionKind(CatalogType type);
// Authorizes one catalog entry the binder retrieved against each layer, ceiling first, when the entry is
// attributable to the caller: tables and views by identity against table policy, function entries against the
// never-bind list and the layer's blocks. Gatekeeper's control plane is refused whoever names it. Records the
// violation and throws PermissionException at the first denial. Every entry is recorded as evidence. A lookup made
// while binding a trusted definition's body is not attributable; see gatekeeper::Provenance.
void AuthorizeObject(const gatekeeper::Layers &layers, const gatekeeper::BindingPolicy &binding, CatalogEntry &entry,
                     gatekeeper::Result &result, bool attributable);
// Authorizes every bound function, aggregate, window, table function, lambda body and dispatched aggregate in a
// plan: the control plane everywhere, the never-bind list and blocks where provenance attributes the name to the
// caller. One walk of the plan per layer, the ceiling's first, so a plan both layers deny is reported by the
// ceiling's walk.
void AuthorizePlan(const gatekeeper::Layers &layers, const gatekeeper::BindingPolicy &binding,
                   const gatekeeper::Provenance &provenance, LogicalOperator &root, gatekeeper::Result &result);
} // namespace duckdb
