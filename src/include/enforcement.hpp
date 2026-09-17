#pragma once

namespace duckdb {
class ClientContext;
class ExtensionLoader;
// Registers the enforcement hooks (per-connection state, planner post-bind check, connection-open
// callback), the global gatekeeper_enforcement setting, and CALL gatekeeper_enforce().
void RegisterEnforcement(ExtensionLoader &loader);
// Whether this connection is latched. The latch lives in the connection's registered state, never in a
// setting, so RESET and native option writes cannot release it.
bool IsEnforced(ClientContext &context);
} // namespace duckdb
