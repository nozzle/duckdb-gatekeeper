#pragma once
#include "validator.hpp"

namespace duckdb {
class ClientContext;
class ExtensionLoader;
// The global authorization ceiling, stored as a DuckDB extension option and re-validated on every read
// because native DBConfig::SetOption bypasses the SET callback.
constexpr const char *POLICY_SETTING = "gatekeeper_policy";
// Throws std::invalid_argument when the setting is missing or malformed.
gatekeeper::Policy GlobalPolicy(ClientContext &context);
// Registers the gatekeeper_policy setting and CALL gatekeeper_configure(), the two ways a host writes the ceiling.
void RegisterPolicySetting(ExtensionLoader &loader);
} // namespace duckdb
