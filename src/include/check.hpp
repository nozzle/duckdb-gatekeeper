#pragma once
#include "duckdb/common/vector.hpp"
#include "duckdb/parser/sql_statement.hpp"
#include "validator.hpp"

namespace duckdb {
class ClientContext;
class LogicalOperator;

// Gatekeeper decides at two boundaries. The binding boundary sees only caller-written text and runs
// before anything binds, so it owns every property that must hold before the engine touches the
// catalog or a reader: statement type, statement count, grammar, and caller-written function names.
// The execution boundary sees a bound plan and owns every property of what actually executes:
// resolved tables, resolved functions, and implementations chosen during binding. gatekeeper_validate
// composes both around a private binder; an enforcing connection runs each at the matching engine hook.

struct TextCheck {
	gatekeeper::Result result;
	// Ambiguous syntax the walker recorded for the execution boundary to resolve against the bound plan.
	gatekeeper::BindingPolicy binding;
	// Populated only when result.allowed: denied text never reaches a binder.
	vector<unique_ptr<SQLStatement>> statements;
};

// Binding boundary. Parses with the connection's parser options and walks the serialized AST against
// the compiled grammar and both policy layers. Never binds and never reads the catalog. Fixed limits
// and unsupported statements produce a denied result; malformed input throws the engine's
// ParserException or InvalidInputException for the caller to map.
TextCheck CheckText(ClientContext &context, const gatekeeper::Policy &policy, const gatekeeper::Policy &ceiling,
                    const string &sql, const gatekeeper::Limits &limits);

// Execution boundary. Authorizes a bound plan against the ceiling and then the request layer, recording
// each violation in result and throwing PermissionException at the first denial.
void CheckPlan(const gatekeeper::Policy &policy, const gatekeeper::Policy &ceiling,
               const gatekeeper::BindingPolicy &binding, LogicalOperator &plan, gatekeeper::Result &result);
} // namespace duckdb
