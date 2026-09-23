#pragma once
#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/enums/statement_type.hpp"
#include "duckdb/common/optional_ptr.hpp"
#include "duckdb/common/vector.hpp"
#include "duckdb/parser/sql_statement.hpp"
#include "duckdb/planner/expression/bound_parameter_data.hpp"
#include "engine_api.hpp"
#include "validator.hpp"

namespace duckdb {
class ClientContext;
class ErrorData;
class LogicalOperator;
struct DBConfig;

// Gatekeeper decides at two boundaries. The binding boundary sees only caller-written text and runs
// before anything binds, so it owns every property that must hold before the engine touches the
// catalog or a reader: statement type, statement count, grammar, and caller-written function names.
// The execution boundary sees a bound plan and owns every property of what actually executes:
// plan operators, resolved tables, resolved functions, and implementations chosen during binding.
// Between them, Authorize binds privately with a catalog-lookup callback so every object the binder
// retrieves, including views that the plan later inlines, is authorized by resolved identity.
// gatekeeper_validate composes all of this into a structured result; an enforcing connection runs the
// same composition at the engine's query hooks and then re-checks the plan the engine executes.

struct TextCheck {
	// One statement the engine runs for the text, admitted at the binding boundary.
	struct Unit {
		unique_ptr<SQLStatement> statement;
		// Ambiguous syntax the walker recorded for the execution boundary to resolve against the bound plan.
		gatekeeper::BindingPolicy binding;
		// What the private bind learned about origin: which names the caller's binders looked up and which a
		// trusted definition introduced. Filled by Authorize; the execution boundary reads it for the engine's plan.
		gatekeeper::Provenance provenance;
		// Enum types the statements before it in the same batch create, which this statement may name in PIVOT
		// IN lists. Nonempty only inside a dynamic PIVOT checked as a whole, where those types do not exist yet:
		// Authorize binds the statement against placeholder values instead (see SubstitutePivotEnums).
		gatekeeper::Names pivot_enums;
		// The unit to check a plan against when no text and no private bind are on record (a Prepare()
		// pre-screen): nothing in the plan can be attributed to the caller, so blocks and table policy alike are
		// deferred to execution, which rebinds inside the query. The read-only operator allowlist still holds.
		static Unit Unattributed();
	};
	// The decision on the text: allowed, or the first denial in the order the engine runs the statements.
	gatekeeper::Result result;
	// The statements the engine runs for the text, in that order, up to the first denied one; denied text
	// never reaches a binder. One for a caller's statement. Several for a dynamic PIVOT, which DuckDB's parser
	// rewrites into the temporary enum types it needs followed by the SELECT that names them, each of which the
	// engine then runs as a statement of its own.
	vector<Unit> units;
};

// Binding boundary. Parses with the connection's parser options and walks the serialized AST against
// the compiled grammar and both policy layers. Never binds and never reads the catalog. Fixed limits
// and unsupported statements produce a denied result; malformed input throws the engine's
// ParserException or InvalidInputException for the caller to map.
TextCheck CheckText(ClientContext &context, const gatekeeper::Layers &layers, const string &sql,
                    const gatekeeper::Limits &limits);

// Which plan the execution boundary is looking at. The private bind's own plan records what the validated
// statement scans; the engine's plan for the same admitted statement is held to that record; a Prepare()
// pre-screen has neither text nor private bind on record and defers everything but plan structure.
enum class PlanOrigin { PRIVATE, ENGINE, PRESCREEN };

// Execution boundary. Requires a read-only statement whose plan contains only reviewed read operators,
// then authorizes the plan against both layers, ceiling first: the tables it scans in one pass, the
// functions it binds in another (AuthorizePlan). The unit supplies what the plan is attributed against:
// the caller's text as the walk recorded it and what the private bind learned about origin; the private
// pass records the base tables the validated statement scans, and the engine pass refuses a plan that scans
// any other, or any more often. The one other root accepted is a dynamic PIVOT's enum type over such a plan
// (PivotEnumPlan). Records each violation in result and throws PermissionException at the first denial.
void CheckPlan(const gatekeeper::Layers &layers, TextCheck::Unit &unit, PlanOrigin origin,
               const StatementProperties &properties, LogicalOperator &plan, gatekeeper::Result &result);

// Private bind of one admitted statement on the caller's connection with the catalog-lookup callback
// and replacement interception, followed by the execution boundary on that plan. Parameter values,
// when supplied, bind exactly as the engine would bind them. Fills unit.provenance. Records violations in
// result and throws PermissionException at the first denial; engine exceptions propagate unchanged.
void Authorize(ClientContext &context, const gatekeeper::Layers &layers, TextCheck::Unit &unit,
               optional_ptr<const engine::ParameterMap> parameters, gatekeeper::Result &result);

// gatekeeper_validate: CheckText, then Authorize, with every outcome mapped to a structured result.
gatekeeper::Result Check(ClientContext &context, const gatekeeper::Layers &layers, const string &sql,
                         const gatekeeper::Limits &limits = gatekeeper::Limits());

// Installs Gatekeeper's replacement-scan callback in first position, once per database.
void InstallReplacementScan(DBConfig &config);

// Describes an error raised while checking or binding as gatekeeper_validate reports it: parser errors as
// 'parser', anything else as 'binding' once the text was admitted and 'invalid_input' before. Returns false for
// errors that are never decisions and must propagate (fatal, internal, out of memory, interrupts).
bool DescribeError(const std::exception &error, bool binding, gatekeeper::Result &result);
bool DescribeError(const ErrorData &error, bool binding, gatekeeper::Result &result);

// One-line description of a denied result for exception messages.
string DenialMessage(const gatekeeper::Result &result);

// Closes a result as denied. Violations make it 'forbidden' and clear the error fields, which belong only to
// error-class outcomes (parser, binding, invalid_input) that carry no violations.
void MarkDenied(gatekeeper::Result &result);
} // namespace duckdb
