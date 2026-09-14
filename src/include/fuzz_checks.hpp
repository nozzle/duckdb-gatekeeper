#pragma once
#ifdef GATEKEEPER_FUZZ
#include "duckdb/common/types/value.hpp"
#include "validator.hpp"

namespace duckdb {
class ClientContext;
// Linked-harness-only access to the production check path with smaller internal limits.
Value GatekeeperCheckForFuzz(ClientContext &context, const string &sql, const gatekeeper::Limits &limits);
// Exercise bind-data comparison directly, including NULLs not routinely compared by the optimizer.
bool GatekeeperBindingsEqualForFuzz(const Value &left, const Value &right, bool option);
} // namespace duckdb
#endif
