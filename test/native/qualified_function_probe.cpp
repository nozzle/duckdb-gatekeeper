// A denied namespace must not run the table implementation's bind callback during private validation.
// The native Prepare() timing residual is intentionally a different contract.
#include "duckdb.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/function/aggregate/distributive_functions.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/parser/parsed_data/create_aggregate_function_info.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "probe_database.hpp"
#include <cstdio>
#include <cstdlib>

using namespace duckdb;

static idx_t binds = 0;
static idx_t aggregate_binds = 0;
#if GATEKEEPER_DUCKDB_MAJOR < 2
static unique_ptr<FunctionData> LoseAggregateStamp(ClientContext &, AggregateFunction &function,
                                                   vector<unique_ptr<Expression>> &) {
	function.catalog_name.clear();
	function.schema_name.clear();
	return nullptr;
}
#endif
#if GATEKEEPER_DUCKDB_MAJOR >= 2
static unique_ptr<FunctionData> BindAggregateProbe(BindAggregateFunctionInput &) {
#else
static unique_ptr<FunctionData> BindAggregateProbe(ClientContext &, AggregateFunction &,
                                                   vector<unique_ptr<Expression>> &) {
#endif
	++aggregate_binds;
	return nullptr;
}

static unique_ptr<FunctionData> BindProbe(ClientContext &, TableFunctionBindInput &, vector<LogicalType> &types,
#if GATEKEEPER_DUCKDB_MAJOR >= 2
                                          vector<Identifier> &names) {
#else
                                          vector<string> &names) {
#endif
	++binds;
	types.push_back(LogicalType::INTEGER);
	names.emplace_back("value");
	return nullptr;
}

static void ScanProbe(ClientContext &, TableFunctionInput &, DataChunk &) {}

static auto Query(Connection &connection, const string &sql) {
	auto result = connection.Query(sql);
	if (result->HasError()) {
		std::fprintf(stderr, "%s: %s\n", sql.c_str(), result->GetError().c_str());
		std::exit(1);
	}
	return result;
}

static Value Cell(Connection &connection, const string &sql) {
	auto result = Query(connection, sql);
	auto chunk = result->Fetch();
	if (!chunk || chunk->size() != 1)
		std::exit(4);
	return chunk->GetValue(0, 0);
}

static void Register(Connection &connection, const string &schema) {
	Query(connection, "BEGIN");
	Query(connection, "CREATE TABLE " + schema + ".registration_marker(i INTEGER)");
	CreateTableFunctionInfo info(TableFunction("probe", {}, ScanProbe, BindProbe));
	info.internal = false;
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	info.SetQualifiedName(QualifiedName("memory", Identifier(schema), "probe"));
#else
	info.catalog = "memory";
	info.schema = schema;
#endif
	Catalog::GetCatalog(*connection.context, "memory").CreateTableFunction(*connection.context, info);
	Query(connection, "COMMIT");
}

int main() {
	DBConfig config;
	ConfigureProbeArtifact(config);
	DuckDB database(nullptr, &config);
	LoadProbeArtifact(database);
	Connection connection(database);
	// Intrinsic windows on 1.5 lose their written alias in the bound expression kind.
	// A host alias grant keeps eligibility open: the scoped system block must still win.
	Query(connection, "CREATE SCHEMA window_host");
	for (const auto &alias : {"rank_dense", "first", "last"}) {
		auto canonical = string(alias) == "rank_dense" ? "dense_rank" : string(alias) + "_value";
		auto args = string(alias) == "rank_dense" ? "" : "1";
		Query(connection, string("CREATE MACRO window_host.") + alias + "() AS 7");
		for (const auto &blocked : {string(alias), string(canonical)}) {
			Query(connection,
			      string("CALL gatekeeper_configure(allowed_functions := ") +
			          "[{catalog:'memory',schema_path:['window_host'],name:'" + alias + "',type:'macro'}], " +
			          "blocked_functions := [{catalog:'system',schema_path:['main'],name:'" + blocked + "'}])");
			Connection window_agent(database);
			Query(window_agent, "CALL gatekeeper_enforce()");
			Query(window_agent, string("SELECT window_host.") + alias + "()");
			for (const auto &name : {string(alias), string(canonical)}) {
				auto sql = "SELECT " + name + "(" + args + ") OVER ()";
				if (Cell(connection, "SELECT code FROM gatekeeper_validate('" + sql + "')").ToString() != "forbidden" ||
				    !window_agent.Query(sql)->HasError())
					return 29;
			}
		}
	}
	Query(connection, "CALL gatekeeper_configure()");
	Query(connection, "CREATE SCHEMA admitted; CREATE SCHEMA denied");
	Register(connection, "admitted");
	Register(connection, "denied");
	Query(connection, "CREATE MACRO admitted.f(x) AS x; CREATE MACRO denied.f(x) AS x");
	Query(
	    connection,
	    "CALL gatekeeper_configure(allowed_functions := [{catalog:'memory',schema_path:['*'],name:'f',type:'macro'}])");
	{
		Connection prepared_agent(database);
		auto admitted_handle = prepared_agent.Prepare("SELECT admitted.f(1)");
		auto denied_handle = prepared_agent.Prepare("SELECT denied.f(1)");
		if (admitted_handle->HasError() || denied_handle->HasError())
			return 26;
		Query(prepared_agent, "CALL gatekeeper_enforce()");
		Query(connection, "CALL gatekeeper_configure(allowed_functions := "
		                  "[{catalog:'memory',schema_path:['*'],name:'f',type:'macro'}], "
		                  "blocked_functions := [{catalog:'memory',schema_path:['denied'],name:'f',type:'macro'}])");
		if (admitted_handle->Execute()->HasError() || !denied_handle->Execute()->HasError())
			return 27;
	}
	// Both namespaces are eligible. A block may deny only the resolved namespace, before its callback.
	Query(connection, "CALL gatekeeper_configure(allowed_functions := "
	                  "[{catalog:'memory',schema_path:['*'],name:'probe',type:'table'}], blocked_functions := "
	                  "[{catalog:'memory',schema_path:['denied'],name:'probe',type:'table'}])");
	if (Cell(connection, "SELECT code FROM gatekeeper_validate('SELECT * FROM denied.probe()')").ToString() !=
	        "forbidden" ||
	    binds != 0)
		return 20;
	if (!Cell(connection, "SELECT allowed FROM gatekeeper_validate('SELECT * FROM admitted.probe()')")
	         .GetValue<bool>() ||
	    binds == 0)
		return 21;
	binds = 0;
	// A request cannot erase the ceiling's qualified block.
	if (Cell(connection,
	         "SELECT code FROM gatekeeper_validate('SELECT * FROM denied.probe()', blocked_functions := [])")
	            .ToString() != "forbidden" ||
	    binds != 0)
		return 22;
	// Covering every eligible md5 identity refuses the entire text before another table can bind.
	Query(connection, "CALL gatekeeper_configure(allowed_functions := "
	                  "[{catalog:'memory',schema_path:['admitted'],name:'probe',type:'table'}], blocked_functions := "
	                  "[{catalog:'system',schema_path:['main'],name:'md5',type:'scalar'}])");
	if (Cell(connection, "SELECT code FROM gatekeeper_validate('SELECT md5(''x'') FROM admitted.probe()')")
	            .ToString() != "forbidden" ||
	    binds != 0)
		return 28;
	// A block of a different kind must not deny the table implementation sharing its leaf.
	Query(connection, "CALL gatekeeper_configure(allowed_functions := "
	                  "[{catalog:'memory',schema_path:['*'],name:'probe',type:'table'}], blocked_functions := "
	                  "[{catalog:'memory',schema_path:['*'],name:'probe',type:'scalar'}])");
	if (!Cell(connection, "SELECT allowed FROM gatekeeper_validate('SELECT * FROM denied.probe()')").GetValue<bool>())
		return 23;
	// abs is reviewed as scalar, never as a table function. Namespace alone cannot confer a default.
	Query(connection, "BEGIN");
	CreateTableFunctionInfo collision(TableFunction("abs", {}, ScanProbe, BindProbe));
	Catalog::GetSystemCatalog(*connection.context).CreateTableFunction(*connection.context, collision);
	Query(connection, "COMMIT");
	Query(connection, "CALL gatekeeper_configure()");
	binds = 0;
	if (Cell(connection, "SELECT code FROM gatekeeper_validate('SELECT * FROM system.main.abs()')").ToString() !=
	        "forbidden" ||
	    binds != 0)
		return 24;
	// Explicitly granting that different kind is a deliberate host decision.
	Query(connection, "CALL gatekeeper_configure(allowed_functions := "
	                  "[{catalog:'system',schema_path:['main'],name:'abs',type:'table'}])");
	if (!Cell(connection, "SELECT allowed FROM gatekeeper_validate('SELECT * FROM system.main.abs()')")
	         .GetValue<bool>() ||
	    binds == 0)
		return 25;
	binds = 0;
	Query(connection, "CALL gatekeeper_configure(allowed_functions := "
	                  "[{catalog:'memory',schema_path:['admitted'],name:'probe',type:'table'}])");
	auto denied = Cell(connection, "SELECT code FROM gatekeeper_validate('SELECT * FROM denied.probe()')");
	if (denied.ToString() != "forbidden" || binds != 0)
		return 1;
	Connection agent(database);
	Query(agent, "CALL gatekeeper_enforce()");
	auto enforced = agent.Query("SELECT * FROM denied.probe()");
	if (!enforced->HasError() || binds != 0)
		return 5;
	auto allowed = Cell(connection, "SELECT allowed FROM gatekeeper_validate('SELECT * FROM admitted.probe()')");
	if (!allowed.GetValue<bool>() || binds == 0)
		return 2;
	binds = 0;
	Query(connection, "CALL gatekeeper_configure(allowed_functions := "
	                  "[{catalog:'memory',schema_path:['admitted'],name:'probe',type:'scalar'}])");
	denied = Cell(connection, "SELECT code FROM gatekeeper_validate('SELECT * FROM admitted.probe()')");
	if (denied.ToString() != "forbidden" || binds != 0)
		return 3;
	// The target is deliberately in system.main, as the builtin dispatcher resolves there directly.
	// A shifted argument must not let its bind callback run before target authorization.
	Query(connection, "BEGIN");
#if GATEKEEPER_DUCKDB_MAJOR >= 2
	auto aggregate = *CountFun::GetFunctions().GetFunctionByOffset(0);
	aggregate.SetName("dispatch_counter");
#else
	auto aggregate = CountFun::GetFunctions().GetFunctionByOffset(0);
	aggregate.name = "dispatch_counter";
#endif
	aggregate.SetBindCallback(BindAggregateProbe);
	CreateAggregateFunctionInfo aggregate_info(aggregate);
	Catalog::GetSystemCatalog(*connection.context).CreateFunction(*connection.context, aggregate_info);
	Query(connection, "COMMIT");
	Query(connection, "CALL gatekeeper_configure(use_default_functions := false, allowed_functions := "
	                  "[{catalog:'system',schema_path:['main'],name:'list_aggregate'},"
	                  "{catalog:'system',schema_path:['main'],name:'list_value'},"
	                  "{catalog:'system',schema_path:['main'],name:'sum'}])");
	denied = Cell(connection, "SELECT code FROM gatekeeper_validate("
	                          "'SELECT l.list_aggregate(''dispatch_counter'', ''sum'') FROM (VALUES ([1])) t(l)')");
	if (denied.ToString() != "forbidden" || aggregate_binds != 0)
		return 6;
	Query(connection, "CALL gatekeeper_configure(allowed_functions := "
	                  "[{catalog:'system',schema_path:['main'],name:'list_aggregate'},"
	                  "{catalog:'system',schema_path:['main'],name:'dispatch_counter',type:'aggregate'}])");
	allowed =
	    Cell(connection, "SELECT allowed FROM gatekeeper_validate('SELECT list_aggregate([1], ''dispatch_counter'')')");
	if (!allowed.GetValue<bool>() || aggregate_binds == 0)
		return 7;
	for (const auto &name : {"min", "max"}) {
		Query(connection, "BEGIN");
		Query(connection, string("CREATE TABLE admitted.") + name + "_marker(i INTEGER)");
#if GATEKEEPER_DUCKDB_MAJOR >= 2
		auto host = *CountFun::GetFunctions().GetFunctionByOffset(0);
		host.SetName(name);
#else
		auto host = CountFun::GetFunctions().GetFunctionByOffset(0);
		host.name = name;
#endif
		host.SetBindCallback(BindAggregateProbe);
		CreateAggregateFunctionInfo info(host);
		info.internal = false;
#if GATEKEEPER_DUCKDB_MAJOR >= 2
		info.SetQualifiedName(QualifiedName("memory", "admitted", name));
#else
		info.catalog = "memory";
		info.schema = "admitted";
#endif
		Catalog::GetCatalog(*connection.context, "memory").CreateFunction(*connection.context, info);
		Query(connection, "COMMIT");
		Query(connection, string("CREATE MACRO main.arg_") + name + "(x,y) AS x");
		Query(connection, string("CALL gatekeeper_configure(allowed_functions := ") +
		                      "[{catalog:'memory',schema_path:['admitted'],name:'" + name + "',type:'aggregate'}])");
		aggregate_binds = 0;
		allowed = Cell(connection, string("SELECT allowed FROM gatekeeper_validate('SELECT admitted.") + name +
		                               "(x) FROM (VALUES (1)) t(x)')");
		if (!allowed.GetValue<bool>() || aggregate_binds == 0)
			return 10;
		// The system implementation and a default macro selecting it still reject that helper shadow.
		for (const auto &sql :
		     {string("SELECT system.main.") + name + "(1)", string("SELECT list_") + name + "([1])"}) {
			denied = Cell(connection, "SELECT code FROM gatekeeper_validate('" + sql + "')");
			if (denied.ToString() != "forbidden")
				return 11;
		}
		Query(connection, string("DROP MACRO main.arg_") + name);
	}
#if GATEKEEPER_DUCKDB_MAJOR < 2
	// A same-name host aggregate observed in this bind must make stamp-loss recovery ambiguous.
	Query(connection, "BEGIN");
	Query(connection, "CREATE TABLE admitted.aggregate_marker(i INTEGER)");
	auto host_mode = CountFun::GetFunctions().GetFunctionByOffset(0);
	host_mode.name = "mode";
	CreateAggregateFunctionInfo host_info(host_mode);
	host_info.internal = false;
	host_info.catalog = "memory";
	host_info.schema = "admitted";
	Catalog::GetCatalog(*connection.context, "memory").CreateFunction(*connection.context, host_info);
	Query(connection, "COMMIT");
	Query(connection, "CALL gatekeeper_configure(allowed_functions := "
	                  "[{catalog:'memory',schema_path:['admitted'],name:'mode',type:'aggregate'}])");
	allowed =
	    Cell(connection, "SELECT allowed FROM gatekeeper_validate('SELECT admitted.mode(x) FROM (VALUES (1)) t(x)')");
	if (!allowed.GetValue<bool>())
		return 8;
	denied = Cell(connection, "SELECT code FROM gatekeeper_validate("
	                          "'SELECT admitted.mode(x), system.main.mode(x) FROM (VALUES (1)) t(x)')");
	if (denied.ToString() != "forbidden")
		return 9;
	Query(connection, "BEGIN");
	Query(connection, "CREATE TABLE admitted.unstamped_marker(i INTEGER)");
	auto unstamped = CountFun::GetFunctions().GetFunctionByOffset(0);
	unstamped.name = "unstamped_host";
	unstamped.SetBindCallback(LoseAggregateStamp);
	CreateAggregateFunctionInfo unstamped_info(unstamped);
	unstamped_info.internal = false;
	unstamped_info.catalog = "memory";
	unstamped_info.schema = "admitted";
	Catalog::GetCatalog(*connection.context, "memory").CreateFunction(*connection.context, unstamped_info);
	Query(connection, "COMMIT");
	Query(connection, "CALL gatekeeper_configure(allowed_functions := "
	                  "[{catalog:'memory',schema_path:['admitted'],name:'unstamped_host',type:'aggregate'}])");
	denied = Cell(connection, "SELECT code FROM gatekeeper_validate('SELECT admitted.unstamped_host(1)')");
	if (denied.ToString() != "forbidden")
		return 12; // An authorized foreign definition does not turn its lost stamp into system provenance.
#endif
	return 0;
}
