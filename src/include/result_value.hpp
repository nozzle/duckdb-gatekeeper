#pragma once
#include "duckdb/common/types.hpp"
#include "duckdb/common/types/value.hpp"
#include "validator.hpp"

namespace duckdb {
// The structured shape of a Gatekeeper decision: the columns of gatekeeper_validate and the body of every
// audit record. Defined in gatekeeper_extension.cpp next to the SQL surface that renders it.
LogicalType ViolationType();
LogicalType IdentityType(bool object);
LogicalType ResultType();
Value ResultValue(const gatekeeper::Result &result);
} // namespace duckdb
