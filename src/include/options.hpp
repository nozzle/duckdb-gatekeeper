#pragma once
#include "duckdb/common/types/value.hpp"
#include "validator.hpp"

namespace gatekeeper {
const std::vector<std::string> &OptionNames();
void CheckOptionShape(const std::string &name, const duckdb::Value &value);
void ApplyOptions(Policy &policy, const std::vector<std::pair<std::string, duckdb::Value>> &options);
duckdb::Value PolicyValue(const Policy &policy);
Policy ReadPolicy(const duckdb::Value &value);
} // namespace gatekeeper
