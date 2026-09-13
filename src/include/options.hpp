#pragma once
#include "duckdb/common/types/value.hpp"
#include "validator.hpp"

namespace gatekeeper {
const std::vector<std::string> &OptionNames();
duckdb::LogicalType OptionType(const std::string &name);
void ApplyOptions(Policy &policy, const std::vector<std::pair<std::string, duckdb::Value>> &options);
duckdb::Value PolicyValue(const Policy &policy);
Policy ReadPolicy(const duckdb::Value &value);
} // namespace gatekeeper
