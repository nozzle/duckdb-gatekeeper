#pragma once
#include "duckdb/common/optional_ptr.hpp"
#include "duckdb/common/string.hpp"
#include "validator.hpp"

namespace duckdb {
class ClientContext;
class ExtensionLoader;
// Registers the enforcement hooks (per-connection state and the planner post-bind check) and
// CALL gatekeeper_enforce(), the only way a connection becomes enforced.
void RegisterEnforcement(ExtensionLoader &loader);
// Whether this connection refuses what the policy denies: it is enforced (the state lives in the connection's
// registered state, never in a setting, so RESET and native option writes cannot release it) and the statement
// in progress, or the setting when no statement is, is not log-only. A log-only connection is checked and
// recorded but binds and executes like an unenforced one.
bool IsEnforcing(ClientContext &context);
// The text of the statement an enforced connection is executing once QueryBegin has admitted it; null on an
// unenforced connection and outside a query (a Prepare() bind), where no statement text is available.
optional_ptr<const string> AdmittedQuery(ClientContext &context);
// The policy snapshot QueryBegin took for that statement, under the same conditions. Every check of one
// statement, including the engine's own bind reaching the replacement-scan gate, must use this one snapshot.
optional_ptr<const gatekeeper::Policy> AdmittedPolicy(ClientContext &context);
} // namespace duckdb
