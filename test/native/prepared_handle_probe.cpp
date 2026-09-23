// A prepared statement handle a client keeps across a policy change is decided under the policy in force at
// each execution, on either engine.
//
// The Python suite's executemany tests couple Prepare() and Execute() inside one call, so a policy change
// between them sits between two prepares as much as between two executions. This probe holds the handle:
// it prepares while the table is allowed, executes, withdraws the table from the policy on another
// connection, executes the same handle (refused), restores the table, and executes the same handle again
// (admitted). Both parameter shapes are exercised: a parameterized statement, whose values are bound at each
// execution, and a parameterless one, whose text DuckDB 2.0 also authorizes at the prepare. Every assertion
// here holds on DuckDB 1.5, where OnExecutePrepared forces the rebind, and on 2.0, where the EXECUTE
// statement's OnRebindPreparedStatement does (src/enforcement.cpp).
//
// Built as gatekeeper_prepared_probe under GATEKEEPER_NATIVE_PROBES and run by the compatibility workflow
// against each candidate engine; exits non-zero with the first failed expectation.
#include "duckdb.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace duckdb;

namespace {

[[noreturn]] void Fail(const string &what) {
	std::fprintf(stderr, "prepared-handle probe: %s\n", what.c_str());
	std::exit(1);
}

void Run(Connection &connection, const string &sql) {
	auto result = connection.Query(sql);
	for (QueryResult *current = result.get(); current; current = current->next.get())
		if (current->HasError())
			Fail(sql + ": " + current->GetError());
}

// The outcome of running a statement or a prepared handle: the row count, or the error.
struct Outcome {
	bool refused = false;
	idx_t rows = 0;
	string error;
};

Outcome Drain(unique_ptr<QueryResult> result) {
	Outcome outcome;
	if (!result || result->HasError()) {
		outcome.refused = true;
		if (result) {
			outcome.error = result->GetError();
			if (result->GetErrorObject().Type() != ExceptionType::PERMISSION)
				Fail("expected a Permission Error, got: " + outcome.error);
			if (outcome.error.find("Gatekeeper denied this statement") == string::npos)
				Fail("expected a Gatekeeper refusal, got: " + outcome.error);
		}
		return outcome;
	}
	while (auto chunk = result->Fetch())
		outcome.rows += chunk->size();
	if (result->HasError())
		Fail("error while reading rows: " + result->GetError());
	return outcome;
}

Outcome Execute(PreparedStatement &handle, vector<Value> values) {
	if (handle.HasError())
		Fail("executing a handle that failed to prepare: " + handle.GetError());
	return Drain(handle.Execute(values));
}

void Allow(Connection &catalog, const string &table) {
	Run(catalog, "CALL gatekeeper_configure(allowed_tables := [{schema: 'reporting', 'table': '" + table + "'}])");
}

void ExpectRows(const Outcome &outcome, idx_t rows, const string &what) {
	if (outcome.refused)
		Fail(what + ": refused, expected " + std::to_string(rows) + " rows: " + outcome.error);
	if (outcome.rows != rows)
		Fail(what + ": " + std::to_string(outcome.rows) + " rows, expected " + std::to_string(rows));
}

void ExpectRefused(const Outcome &outcome, const string &what) {
	if (!outcome.refused)
		Fail(what + ": admitted with " + std::to_string(outcome.rows) + " rows, expected a refusal");
}

} // namespace

int main() {
	DuckDB db(nullptr);
	Connection catalog(db);
	Run(catalog, "CREATE SCHEMA reporting; CREATE TABLE reporting.leak(x INTEGER); "
	             "INSERT INTO reporting.leak VALUES (1), (2); CREATE TABLE reporting.orders(x INTEGER); "
	             "CREATE SCHEMA secret; CREATE TABLE secret.salaries(x INTEGER)");
	Allow(catalog, "*");

	Connection agent(db);
	Run(agent, "CALL gatekeeper_enforce()");
	ExpectRefused(Drain(agent.Query("SELECT x FROM secret.salaries")), "enforcement did not latch");
	ExpectRows(Drain(agent.Query("SELECT x FROM reporting.leak")), 2, "allowed table before any prepare");

	// Prepare both shapes while the table is allowed, and keep the handles.
	const vector<Value> one{Value::INTEGER(0)};
	const vector<Value> none;
	auto with_parameter = agent.Prepare("SELECT x FROM reporting.leak WHERE x > ?");
	auto without_parameter = agent.Prepare("SELECT x FROM reporting.leak");
	if (with_parameter->HasError())
		Fail("parameterized prepare while allowed: " + with_parameter->GetError());
	if (without_parameter->HasError())
		Fail("parameterless prepare while allowed: " + without_parameter->GetError());
	ExpectRows(Execute(*with_parameter, one), 2, "parameterized handle, allowed");
	ExpectRows(Execute(*without_parameter, none), 2, "parameterless handle, allowed");

	// Withdraw the table on the catalog connection; the retained handles must be refused.
	Allow(catalog, "orders");
	ExpectRefused(Execute(*with_parameter, one), "parameterized handle after the table was withdrawn");
	ExpectRefused(Execute(*without_parameter, none), "parameterless handle after the table was withdrawn");
	// A refusal leaves the connection usable for the next statement.
	ExpectRows(Drain(agent.Query("SELECT 1")), 1, "plain statement after a refused execution");

	// A handle prepared while the table is withdrawn never produces rows: DuckDB 2.0 refuses the parameterless
	// prepare itself (its text is authorized as any parameterless statement's is), 1.5 binds it before any hook
	// and refuses the execution. Either way the outcome is a refusal, and a handle that did prepare is decided
	// at each execution like any other.
	auto prepared_while_withdrawn = agent.Prepare("SELECT x FROM reporting.leak");
	if (!prepared_while_withdrawn->HasError())
		ExpectRefused(Execute(*prepared_while_withdrawn, none), "handle prepared while the table was withdrawn");
	else if (prepared_while_withdrawn->GetErrorObject().Type() != ExceptionType::PERMISSION ||
	         prepared_while_withdrawn->GetError().find("Gatekeeper denied this statement") == string::npos)
		Fail("prepare while withdrawn failed with something other than a Gatekeeper refusal: " +
		     prepared_while_withdrawn->GetError());

	// Restore the table; the same handles are admitted again.
	Allow(catalog, "*");
	ExpectRows(Execute(*with_parameter, one), 2, "parameterized handle after the table was restored");
	ExpectRows(Execute(*without_parameter, none), 2, "parameterless handle after the table was restored");
	if (!prepared_while_withdrawn->HasError())
		ExpectRows(Execute(*prepared_while_withdrawn, none), 2,
		           "handle prepared while withdrawn, after the table was restored");

	std::printf("prepared-handle probe: ok on DuckDB %s\n", DuckDB::LibraryVersion());
	return 0;
}
