// A denied namespace must not run the table implementation's bind callback during private validation.
// The native Prepare() timing residual is intentionally a different contract.
#include "duckdb.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include <cstdio>
#include <cstdlib>

using namespace duckdb;

static idx_t binds = 0;

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
	CreateTableFunctionInfo info(TableFunction("probe", {}, ScanProbe, BindProbe));
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
	DuckDB database(nullptr);
	Connection connection(database);
	Query(connection, "CREATE SCHEMA admitted; CREATE SCHEMA denied");
	Register(connection, "admitted");
	Register(connection, "denied");
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
	return denied.ToString() == "forbidden" && binds == 0 ? 0 : 3;
}
