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
// How the replacement-scan gate treats a bind on this connection that is not inside Gatekeeper's own private
// bind. OPEN: unenforced, or log-only and already decided, so the engine binds as it would anywhere. ENFORCE:
// a denied reader is recorded and refused. LOG_ONLY: the statement (or the Prepare() outside any statement)
// has not been decided yet, because parameters defer authorization to the engine's bind or because no
// statement is in progress; a denied reader is recorded under the snapshotted mode and the bind continues.
// The enforced state lives in the connection's registered state, never in a setting, so RESET and native
// option writes cannot release it.
enum class GateMode : uint8_t { OPEN, ENFORCE, LOG_ONLY };
GateMode ReplacementGate(ClientContext &context);
// Marks the statement in progress, or the Prepare() bind outside one, as decided at the gate, so the hooks
// the engine reaches afterwards do not decide it again.
void MarkGateDecided(ClientContext &context);
// The text of the statement an enforced connection is executing once QueryBegin has admitted it; null on an
// unenforced connection and outside a query (a Prepare() bind), where no statement text is available.
optional_ptr<const string> AdmittedQuery(ClientContext &context);
// The policy snapshot QueryBegin took for that statement, under the same conditions. Every check of one
// statement, including the engine's own bind reaching the replacement-scan gate, must use this one snapshot.
optional_ptr<const gatekeeper::Policy> AdmittedPolicy(ClientContext &context);
} // namespace duckdb
