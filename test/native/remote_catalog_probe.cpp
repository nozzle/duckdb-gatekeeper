// A counted, in-process remote catalog: no network or Quack dependency. Refused normal SQL routes
// must leave its callback count at zero. Separately assert the residual pre-hook dispatch behavior
// of unsupported already-connected/native-mutated sessions, so a late refusal is never mistaken
// for pre-callback protection. Built/run with the other native probes on both engine lines.
#include "duckdb.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "probe_database.hpp"

#if GATEKEEPER_DUCKDB_MAJOR >= 2
#include "duckdb/catalog/duck_catalog.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/subqueryref.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/transaction/duck_transaction_manager.hpp"
#endif

#include <cstdio>
#include <cstdlib>

using namespace duckdb;

namespace {

[[noreturn]] void Fail(const string &message) {
	std::fprintf(stderr, "remote-catalog probe: %s\n", message.c_str());
	std::exit(1);
}

void Require(bool condition, const string &message) {
	if (!condition)
		Fail(message);
}

void Run(Connection &connection, const string &sql) {
	auto result = connection.Query(sql);
	for (QueryResult *current = result.get(); current; current = current->next.get())
		if (current->HasError())
			Fail(sql + ": " + current->GetError());
}

void Denied(unique_ptr<QueryResult> result, const string &message = "Gatekeeper denied this statement") {
	Require(result && result->HasError(), "expected refusal: " + message);
	Require(result->GetErrorObject().Type() == ExceptionType::PERMISSION &&
	            result->GetError().find(message) != string::npos,
	        "wrong refusal: " + result->GetError());
}

void NotLatched(Connection &connection) {
	Require(!connection.context->registered_state->Get<ClientContextState>("gatekeeper_enforced"),
	        "activation unexpectedly latched");
}

void LocalRoutes(DuckDB &db) {
	Connection host(db);
	// Trusted SQL definitions must not launder Gatekeeper's control plane through SELECT/query().
	Run(host, "CREATE MACRO activation() AS TABLE SELECT * FROM gatekeeper_enforce()");
	Run(host, "CREATE MACRO indirect_activation() AS TABLE "
	          "SELECT * FROM query('SELECT * FROM gatekeeper_enforce()')");
	Run(host, "CALL gatekeeper_configure(allowed_functions := [{schema_path:['main'],name:'activation'}, "
	          "{schema_path:['main'],name:'indirect_activation'}])");
	Connection agent(db);
	Run(agent, "CALL gatekeeper_enforce()");
	// Macro binding rethrows the catalog callback's Permission Error with a query location.
	Denied(agent.Query("SELECT * FROM activation()"), "resolved function is not allowed");
	Denied(agent.Query("SELECT * FROM indirect_activation()"), "resolved function is not allowed");
	Run(agent, "SELECT 1");
	auto handle = agent.Prepare("SELECT ?::INTEGER");
	Require(!handle->HasError(), "local parameterized prepare failed");
	auto result = handle->Execute(42);
	Require(!result->HasError(), "local parameterized execution failed");
	Run(host, "CALL gatekeeper_configure()");
}

#if GATEKEEPER_DUCKDB_MAJOR >= 2
struct RemoteState : StorageExtensionInfo {
	vector<string> calls;
	idx_t attaches = 0;
	bool local_activation = false;
};

class RemoteCatalog : public DuckCatalog {
  public:
	RemoteCatalog(AttachedDatabase &db, RemoteState &state) : DuckCatalog(db), state(state) {}
	bool Supports(RemoteCapability capability) const override { return capability == RemoteCapability::CONNECT; }
	unique_ptr<TableRef> RemoteExecute(ClientContext &context, const string &sql) override {
		state.calls.push_back(sql); // The observable effect occurs before QueryBegin can refuse anything.
		Parser parser(context.GetParserOptions());
		parser.ParseQuery(state.local_activation ? "SELECT * FROM gatekeeper_enforce()" : "SELECT 42 AS remote_value");
		return make_uniq<SubqueryRef>(unique_ptr_cast<SQLStatement, SelectStatement>(std::move(parser.statements[0])));
	}

  private:
	RemoteState &state;
};

unique_ptr<Catalog> Attach(optional_ptr<StorageExtensionInfo> info, ClientContext &, AttachedDatabase &db,
                           const string &, AttachInfo &, AttachOptions &) {
	auto &state = static_cast<RemoteState &>(*info);
	state.attaches++;
	return make_uniq<RemoteCatalog>(db, state);
}

unique_ptr<TransactionManager> Transactions(optional_ptr<StorageExtensionInfo>, AttachedDatabase &db, Catalog &) {
	return make_uniq<DuckTransactionManager>(db);
}

// Trusted native code changes state AFTER the dispatch decision but BEFORE the local latch body.
// This deliberately exercises the otherwise unreachable activation boundary, including an expired
// weak target. It is a test of the latch check, not a supported integration or a security hook.
struct ConnectBeforeLatch : ClientContextState {
	shared_ptr<AttachedDatabase> target;
	Connection &host;
	bool detach;
	ConnectBeforeLatch(shared_ptr<AttachedDatabase> target, Connection &host, bool detach)
	    : target(std::move(target)), host(host), detach(detach) {}
	void QueryBegin(ClientContext &context) override {
		if (!target)
			return;
		context.ConnectToCatalog(target);
		if (detach)
			Run(host, "DETACH remote");
		target.reset();
	}
};

void RemoteRoutes(DuckDB &db, RemoteState &state) {
	Connection host(db);
	Run(host, "ATTACH ':memory:' AS remote (TYPE remote_probe)");
	auto target = DatabaseManager::Get(*host.context).GetDatabase(Identifier("remote"));
	Connection agent(db);
	// Retained handles prepared before activation cannot introduce CONNECT either.
	auto connect_handle = agent.Prepare("CONNECT remote");
	Require(!connect_handle->HasError(), "CONNECT prepare before enforcement failed");
	Run(agent, "CALL gatekeeper_enforce()");
	for (const auto &sql : {"CONNECT remote", "CONNECT 'remote_probe::memory:'", "CONNECT LOCAL", "CONNECT",
	                        "DISCONNECT", "CONNECT remote; SELECT 123"}) {
		Denied(agent.Query(sql));
		Require(!agent.context->IsConnected(), string(sql) + " changed connection state");
		Require(state.calls.empty(), string(sql) + " reached RemoteExecute");
		Require(state.attaches == 1, string(sql) + " performed an implicit attach");
	}
	auto sql_prepare = agent.Query("PREPARE c AS CONNECT remote");
	Require(sql_prepare->HasError() && sql_prepare->GetError().find("not a preparable statement") != string::npos,
	        "expected the engine parser to reject SQL PREPARE CONNECT");
	auto denied_prepare = agent.Prepare("CONNECT remote");
	Require(denied_prepare->HasError() &&
	            denied_prepare->GetError().find("Gatekeeper denied this statement") != string::npos,
	        "CONNECT prepare after activation was not refused by Gatekeeper");
	Denied(connect_handle->Execute());
	Run(agent, "SELECT 1");
	Require(state.calls.empty(), "supported prepared route reached RemoteExecute");
	std::printf("remote-catalog probe: normal CONNECT/query/prepared refusals: zero remote callbacks\n");

	// A successful SQL result on an already-connected session need not be an activation at all.
	Connection connected(db);
	Run(connected, "CONNECT remote");
	Run(connected, "CALL gatekeeper_enforce()");
	Require(state.calls.size() == 1 && state.calls.back() == "CALL gatekeeper_enforce()",
	        "already-connected activation did not route its original text");
	NotLatched(connected);
	// Even if the returned local plan reaches the activation body, refusal is AFTER the callback.
	state.local_activation = true;
	Denied(connected.Query("CALL gatekeeper_enforce()"), "cannot run on a CONNECT-ed connection");
	Require(state.calls.size() == 2, "local activation refusal incorrectly assumed pre-callback");
	NotLatched(connected);
	state.local_activation = false;
	Run(connected, "DISCONNECT");

	// Latch refusal for live and stale connected state when the LOCAL body really is reached.
	for (bool detach : {false, true}) {
		Connection activation(db);
		activation.context->registered_state->Insert("probe_connect",
		                                             make_shared_ptr<ConnectBeforeLatch>(target, host, detach));
		// Log-only cannot weaken the activation prerequisite either.
		Run(host, string("SET gatekeeper_log_only = ") + (detach ? "true" : "false"));
		if (detach)
			target.reset();
		auto before = state.calls.size();
		Denied(activation.Query("CALL gatekeeper_enforce()"), "cannot run on a CONNECT-ed connection");
		Require(activation.context->IsConnected(), "expected connected flag at latch");
		Require(bool(activation.context->TryGetConnectedCatalog()) == !detach, "wrong target liveness at latch");
		NotLatched(activation);
		Require(state.calls.size() == before, "local latch test unexpectedly routed SQL");
		activation.context->DisconnectFromCatalog();
	}
	Run(host, "SET gatekeeper_log_only = false");
	Run(host, "ATTACH ':memory:' AS remote (TYPE remote_probe)");
	target = DatabaseManager::Get(*host.context).GetDatabase(Identifier("remote"));

	// Native mutation of an already-enforced session bypasses the normal CONNECT refusal.
	auto plain = agent.Prepare("SELECT 42");
	auto parameterized = agent.Prepare("SELECT ?::INTEGER");
	Require(!plain->HasError() && !parameterized->HasError(), "local prepare before native mutation failed");
	agent.context->ConnectToCatalog(target);
	auto before = state.calls.size();
	Denied(agent.Query("CREATE TABLE untrusted_text(i INTEGER)"));
	Require(state.calls.size() == before + 1 && state.calls.back() == "CREATE TABLE untrusted_text(i INTEGER)",
	        "native-mutated session no longer exhibits pre-hook dispatch; review the upstream boundary");
	auto plain_result = plain->Execute();
	Require(!plain_result->HasError() && state.calls.size() == before + 2,
	        "parameterless handle on native-mutated session did not route");
	auto parameterized_result = parameterized->Execute(42);
	Require(parameterized_result->HasError() &&
	            parameterized_result->GetError().find("Parameterized prepared statements") != string::npos &&
	            state.calls.size() == before + 2,
	        "engine parameterized connected execution refusal changed");
	auto remote_prepare = agent.Prepare("SELECT 42");
	Require(remote_prepare->HasError() &&
	            remote_prepare->GetError().find("prepared statement was not registered") != string::npos &&
	            state.calls.size() == before + 3,
	        "Prepare on native-mutated session did not dispatch before its missing-handle error");
	agent.context->DisconnectFromCatalog();

	// Detached targets retain IsConnected. Engine refuses before hooks, not a Gatekeeper decision.
	Run(connected, "CONNECT remote");
	Run(host, "DETACH remote");
	// Detachment removes the alias, but a native owner can keep the weak routing target alive.
	before = state.calls.size();
	Run(connected, "SELECT 123");
	Require(state.calls.size() == before + 1 && connected.context->TryGetConnectedCatalog(),
	        "detached target held by native code no longer routes; review upstream semantics");
	target.reset();
	before = state.calls.size();
	auto stale = connected.Query("CALL gatekeeper_enforce()");
	Require(stale->HasError() && stale->GetError().find("detached") != string::npos,
	        "stale SQL activation must fail in the engine");
	Require(connected.context->IsConnected() && !connected.context->TryGetConnectedCatalog(), "not stale");
	NotLatched(connected);
	Require(state.calls.size() == before, "stale target received callback");
	Run(connected, "DISCONNECT");
	Run(connected, "CALL gatekeeper_enforce()");
	Denied(connected.Query("CREATE TABLE denied(i INTEGER)"));

	// Log-only previews policy decisions, but cannot change the routing state. Retained handles
	// and comments/case variations must obey the same AST-based exception as ordinary SQL.
	Run(host, "ATTACH ':memory:' AS remote (TYPE remote_probe)");
	Run(host, "SET gatekeeper_log_only = true");
	before = state.calls.size();
	auto attaches = state.attaches;
	for (const auto &sql : {"CONNECT remote", "/* routing */ CoNnEcT remote", "CONNECT 'remote_probe::memory:'",
	                        "-- routing\n DiScOnNeCt", "CONNECT remote; SELECT 123"})
		Denied(agent.Query(sql));
	// The size-limit denial normally becomes advisory in log-only. Routing must be recognized
	// before that early return, even when a long comment pushes the statement over the limit.
	Denied(agent.Query("CONNECT /*" + string(8388608, 'x') + "*/ remote"));
	Denied(connect_handle->Execute());
	auto log_only_prepare = agent.Prepare("CONNECT remote");
	Require(log_only_prepare->HasError() &&
	            log_only_prepare->GetError().find("Gatekeeper denied this statement") != string::npos,
	        "log-only CONNECT prepare was not refused");
	Require(!agent.context->IsConnected() && state.calls.size() == before && state.attaches == attaches,
	        "log-only routing control changed state or reached a remote callback");
	Run(agent, "CREATE TABLE log_only_text(i INTEGER)");
	Run(agent, "SELECT 'CONNECT remote' AS text");
	Run(host, "SET gatekeeper_log_only = false");
	Denied(agent.Query("CREATE TABLE after_log_only(i INTEGER)"));
	Require(state.calls.size() == before, "log-only rollout failed to preserve local routing");
	std::printf("remote-catalog probe: log-only routing refusals and rollout switch: zero remote callbacks\n");
	std::printf("remote-catalog probe: local live/stale latch checks and documented pre-hook limitations: ok\n");
}
#endif

} // namespace

int main() {
	DBConfig config;
	ConfigureProbeArtifact(config);
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	auto state = make_shared_ptr<RemoteState>();
	auto extension = make_shared_ptr<StorageExtension>();
	extension->attach = Attach;
	extension->create_transaction_manager = Transactions;
	extension->storage_info = state;
	StorageExtension::Register(config, "remote_probe", extension);
#endif
	DuckDB db(nullptr, &config);
	LoadProbeArtifact(db);
	LocalRoutes(db);
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	RemoteRoutes(db, *state);
#endif
	std::printf("remote-catalog probe: ok on DuckDB %s\n", DuckDB::LibraryVersion());
	return 0;
}
