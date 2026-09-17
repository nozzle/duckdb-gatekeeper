#pragma once
#include "validator.hpp"

namespace duckdb {
class ClientContext;
// The global authorization ceiling, stored as a DuckDB extension option and re-validated on every read
// because native DBConfig::SetOption bypasses the SET callback.
constexpr const char *POLICY_SETTING = "gatekeeper_policy";
// Throws std::invalid_argument when the setting is missing or malformed.
gatekeeper::Policy GlobalPolicy(ClientContext &context);
} // namespace duckdb
