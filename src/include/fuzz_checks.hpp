#pragma once
#ifdef GATEKEEPER_FUZZ
#include "duckdb/common/types/value.hpp"
#include "validator.hpp"

namespace duckdb {
class ClientContext;
// Linked-harness-only access to the production check path with smaller internal limits.
Value GatekeeperCheckForFuzz(ClientContext &context, const string &sql, const gatekeeper::Limits &limits);
} // namespace duckdb
#endif
