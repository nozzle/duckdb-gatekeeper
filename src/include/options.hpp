#pragma once
#include "duckdb/common/types/value.hpp"
#include "validator.hpp"

namespace gatekeeper {
duckdb::LogicalType OptionType(const std::string &name);
void ApplyOptions(Policy &policy, const std::vector<std::pair<std::string, duckdb::Value>> &options);
} // namespace gatekeeper
