#pragma once
#include "validator.hpp"

namespace duckdb {
class CatalogEntry;
class LogicalOperator;
void AuthorizeObject(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding, CatalogEntry &entry,
                     gatekeeper::Result &result);
void AuthorizePlan(const gatekeeper::Policy &policy, const gatekeeper::BindingPolicy &binding, LogicalOperator &root,
                   gatekeeper::Result &result);
} // namespace duckdb
