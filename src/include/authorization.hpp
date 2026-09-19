#pragma once
#include "validator.hpp"

namespace duckdb {
class CatalogEntry;
class LogicalOperator;
enum class CatalogType : uint8_t;
// The kind a function entry is reported as in Result::functions (scalar, aggregate, table, macro, table_macro,
// pragma), or null for every catalog entry that is not a function.
const char *FunctionKind(CatalogType type);
// Authorizes one catalog entry the binder retrieved: tables and views by identity against table policy, function
// entries against the never-bind list and, when the name is attributable to the caller, the policy's blocks.
// A lookup made while binding a trusted definition's body is not attributable; see gatekeeper::Provenance.
void AuthorizeObject(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding, CatalogEntry &entry,
                     gatekeeper::Result &result, bool attributable = true);
// Authorizes every bound function, aggregate, window, table function, lambda body and dispatched aggregate in a
// plan: the never-bind list everywhere, blocks where provenance attributes the name to the caller.
void AuthorizePlan(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding,
                   const gatekeeper::Provenance &provenance, LogicalOperator &root, gatekeeper::Result &result);
} // namespace duckdb
