#pragma once
#include "duckdb/common/types.hpp"
#include "duckdb/common/types/value.hpp"
#include "validator.hpp"

namespace duckdb {
// The structured shape of a Gatekeeper decision: the columns of gatekeeper_validate and the body of every
// audit record.
LogicalType ResultType();
Value ResultValue(const gatekeeper::Result &result);
} // namespace duckdb
