import duckdb
import pytest

from test_gatekeeper import db
from typed_helpers import validate, configure


def test_named_prepared_and_row_varying_options(db):
    result = db.execute("SELECT gatekeeper_validate(?, blocked_functions := ?)", ["SELECT md5('x')", ["md5"]]).fetchone()[0]
    assert not result["allowed"]
    assert result["violations"][0]["function_name"] == "md5"
    rows = db.execute("""SELECT r.allowed, count(*) FROM (
        SELECT gatekeeper_validate('SELECT md5(''x'')', blocked_functions :=
            CASE WHEN i%2=0 THEN []::VARCHAR[] ELSE ['md5'] END) r
        FROM range(10000) t(i)) GROUP BY ALL ORDER BY 1""").fetchall()
    assert rows == [(False, 5000), (True, 5000)]


@pytest.mark.parametrize("args", [
    "'{}'", "resolve_objects := false", "unknown := true", "limits := {max_statements:1}",
    "use_default_functions := 'false'", "use_default_functions := 1", "max_statements := 1.5",
    "allowed_functions := 'sum'", "allowed_functions := [1,2]", "allowed_tables := [1]",
    "allowed_tables := ['main.t']",
    "blocked_functions := [], blocked_functions := ['md5']",
    "allow_dynamic_sql := true",  # unknown option
    "allow_table_functions := true", "allow_table_functions := false",  # removed option
    "check_functions := true", "check_functions := false",
    "allow_recursive_ctes := true", "allow_recursive_ctes := false",
    "max_ast_bytes := 8388608", "max_ast_nodes := 100000", "max_ast_depth := 512",
])
def test_rejected_signatures(db,args):
    with pytest.raises(duckdb.Error):
        db.execute("SELECT gatekeeper_validate('SELECT 1'," + args + ")")
    with pytest.raises(duckdb.Error):
        db.execute("CALL gatekeeper_configure(" + args.replace("'SELECT 1',", "") + ")")


@pytest.mark.parametrize("options", [
    {"blocked_functions":None}, {"blocked_functions":[None]}, {"blocked_functions":[""]},
    {"allowed_tables":[None]}, {"allowed_tables":[{"table":"t"}]}, {"allowed_tables":[{"schema":"main","table":"t","extra":"x"}]},
    {"max_statements":0}, {"max_statements":-1},
])
def test_invalid_typed_values(db,options):
    result = validate(db,"SELECT 1", options)
    assert not result["allowed"] and result["code"] == "invalid_input", result


def test_configure_replacement_and_independent_limits(db):
    assert configure(db,{"blocked_functions":["md5"],"max_statements":2})
    assert validate(db,"SELECT 1; SELECT 2", {"use_default_functions":False})["allowed"]
    assert not validate(db,"SELECT md5('x')")["allowed"]
    assert not validate(db,"SELECT md5('x')", {"blocked_functions":[]})["allowed"]
    configure(db)
    assert validate(db,"SELECT md5('x')")["allowed"]


def test_struct_table_parameters(db):
    db.execute("CREATE TABLE t(x INT)")
    for entries in [[{"schema":"main","table":"t"}], [{"catalog":"memory","schema":"main","table":"t"}]]:
        assert validate(db,"SELECT * FROM t",{"allowed_tables":entries})["allowed"]
    assert not validate(db,"SELECT * FROM t",{"allowed_tables":[]})["allowed"]


def test_structured_object_and_limit_diagnostics(db):
    db.execute("CREATE SCHEMA secret; CREATE TABLE secret.t(x INT)")
    result=validate(db,"SELECT * FROM secret.t",{"allowed_tables":[]})
    violation=result["violations"][0]
    assert violation["rule"]=="table"
    assert (violation["catalog"],violation["schema"],violation["table"])==("memory","secret","t")
    assert violation["function_name"]==""
    result=validate(db,"SELECT 1;SELECT 2")
    assert result["code"]=="forbidden" and result["violations"][0]["rule"]=="limit"
    result=validate(db,"SELECT md5('x')",{"blocked_functions":["md5"]})
    assert result["violations"][0]["position"]==7
    result=validate(db,"SELECT * FROM")
    assert result["position"]==13 and result["error_type"]=="parser"


def test_file_backed_view_requires_own_permission(db,tmp_path):
    path=str(tmp_path/"backing.parquet").replace("'","''")
    db.execute(f"COPY (SELECT 42 AS x) TO '{path}' (FORMAT PARQUET)")
    db.execute(f"CREATE VIEW v AS SELECT * FROM read_parquet('{path}')")
    assert not validate(db,"SELECT * FROM v",{"allowed_tables":[]})["allowed"]
    assert validate(db,"SELECT * FROM v",{"allowed_tables":[{"schema":"main","table":"v"}]})["allowed"]
    result = validate(db, f"SELECT * FROM read_parquet('{path}')")
    assert result["code"] == "forbidden" and result["violations"][0]["rule"] == "function"
    assert not validate(db, "SELECT * FROM v", {"blocked_functions": ["read_parquet"]})["allowed"]


def test_view_and_underlying_table_must_both_pass(db):
    db.execute("CREATE TABLE t(x INT); CREATE VIEW v AS SELECT * FROM t")
    table={"schema":"main","table":"t"}
    view={"schema":"main","table":"v"}
    assert not validate(db,"SELECT * FROM v",{"allowed_tables":[view]})["allowed"]
    assert not validate(db,"SELECT * FROM v",{"allowed_tables":[table]})["allowed"]
    assert validate(db,"SELECT * FROM v",{"allowed_tables":[view,table]})["allowed"]


def test_dynamic_table_lookup_keeps_object_policy(db):
    db.execute("CREATE TABLE secret(x INT)")
    options={"allowed_functions":["query_table","query"],"allowed_tables":[]}
    for sql in ["SELECT * FROM query_table('secret')", "SELECT * FROM query('SELECT * FROM secret')"]:
        result=validate(db,sql,options)
        assert not result["allowed"], (sql,result)


def test_python_replacement_scan_rejected(db):
    # A relation replacement scan is local and needs no optional pandas dependency. It resolves to a
    # subquery, not a table function, so it is denied even when replacement scans are enabled.
    db.execute("SET threads=1")
    host_data=db.sql("SELECT 1 AS x")
    assert db.execute("SELECT * FROM host_data").fetchone()==(1,)
    # The Python scan resolves names in the calling frame, so validate from this frame directly.
    for options in ["allowed_tables := []", "allow_replacement_scans := true"]:
        db.execute("CALL gatekeeper_configure(" + options + ")")
        result=db.execute("SELECT gatekeeper_validate('SELECT * FROM host_data', " + options + ")").fetchone()[0]
        assert not result["allowed"] and result["code"]=="forbidden", result
        assert result["violations"][0]["rule"]=="replacement_scan"
        assert result["objects"] == result["functions"] == []


def test_no_prebind_io_for_blocked_reader(db):
    result=validate(db,"SELECT * FROM read_parquet('/does/not/exist.parquet')")
    assert result["code"]=="forbidden"
    assert result["violations"][0]["rule"]=="function"
    assert result["error_message"]==""


def test_bind_callback_input_errors_have_binding_code(db):
    result=validate(db,"SELECT map_concat(1)")
    assert not result["allowed"] and result["code"]=="binding", result
    result=validate(db,"SELECT 1",{"max_statements":0})
    assert not result["allowed"] and result["code"]=="invalid_input", result


@pytest.mark.parametrize("name", ["exists.duckdb", "missing.duckdb", "x.db", "x.ddb", "x.avro", "x.shp", "x.gpkg", "x.fgb",
                                  "data.parquet?", "nope.parquet?", "x.json?", "x.jsonl?", "x.ndjson?", "x.csv?", "x.tsv?"])
def test_relative_file_forms_rejected_before_binding(db, tmp_path, monkeypatch, name):
    with duckdb.connect(str(tmp_path / "exists.duckdb")) as local:
        local.execute("CREATE TABLE t(x INT)")
    (tmp_path / "data.parquetx").write_bytes(b"not parquet")
    monkeypatch.chdir(tmp_path)
    result = validate(db, "SELECT * FROM '" + name + "'")
    assert result["code"] == "forbidden" and result["error_message"] == "", result
    assert result["violations"][0]["rule"] == "replacement_scan"


def test_file_name_opt_in_only_authorizes_catalog_object(db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db.execute('CREATE TABLE "data.parquet"(x INT)')
    assert not validate(db, 'SELECT * FROM "data.parquet"')["allowed"]
    configure(db, {"allow_replacement_scans": True})
    result = validate(db, 'SELECT * FROM "data.parquet"', {"allow_replacement_scans": True})
    assert result["allowed"] and result["objects"][0]["type"] == "table"
    result = validate(db, "SELECT * FROM 'missing.duckdb'", {"allow_replacement_scans": True})
    assert not result["allowed"] and result["code"] == "forbidden"
    assert result["violations"][0]["function_name"] == "read_duckdb"


def test_replacement_scan_authorizes_resolved_reader_without_prebind_io(db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db.execute("COPY (SELECT 1 AS x) TO 'data.parquet'")
    (tmp_path / "data.csv").write_text("x\n42\n")
    configure(db, {"allow_replacement_scans": True})
    # Enabled but reader not admitted: denied at the callback, so a missing path never binds.
    for name in ["data.parquet", "/does/not/exist.parquet", "data.csv", "s3://bucket/key.parquet"]:
        result = validate(db, f"SELECT * FROM '{name}'")
        assert result["code"] == "forbidden" and result["error_message"] == "", (name, result)
        violation = result["violations"][0]
        assert violation["rule"] == "function" and violation["table"] == name
        assert violation["function_name"] in {"parquet_scan", "read_csv_auto"}
    configure(db, {"allow_replacement_scans": True, "allowed_functions": ["parquet_scan", "read_csv_auto"]})
    for name, function in [("data.parquet", "parquet_scan"), ("data.csv", "read_csv_auto")]:
        result = validate(db, f"SELECT * FROM '{name}'")
        assert result["allowed"], (name, result)
        assert result["objects"] == [{"catalog": "", "schema": "", "table": name, "type": "replacement"}]
        assert [f["name"] for f in result["functions"]] == [function]
    # An admitted reader still surfaces real binding errors for missing files.
    assert validate(db, "SELECT * FROM '/does/not/exist.parquet'")["code"] == "binding"
    # Requests narrow only: they cannot enable scans the global policy disables, and can disable them.
    assert not validate(db, "SELECT * FROM 'data.parquet'", {"allow_replacement_scans": False})["allowed"]
    assert not validate(db, "SELECT * FROM 'data.parquet'", {"blocked_functions": ["parquet_scan"]})["allowed"]
    configure(db, {"allowed_functions": ["parquet_scan"]})
    result = validate(db, "SELECT * FROM 'data.parquet'", {"allow_replacement_scans": True})
    assert result["code"] == "forbidden" and result["violations"][0]["rule"] == "replacement_scan"
    # allowed_tables governs catalog objects, not reader capabilities, matching range().
    configure(db, {"allow_replacement_scans": True, "allowed_functions": ["parquet_scan"], "allowed_tables": []})
    assert validate(db, "SELECT * FROM 'data.parquet'")["allowed"]


def test_replacement_scan_inside_view_requires_admitted_reader(db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db.execute("COPY (SELECT 1 AS x) TO 'data.parquet'; CREATE VIEW v AS SELECT * FROM 'data.parquet'")
    configure(db, {"allow_replacement_scans": True})
    result = validate(db, "SELECT * FROM v")
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "parquet_scan"
    configure(db, {"allow_replacement_scans": True, "allowed_functions": ["parquet_scan"]})
    result = validate(db, "SELECT * FROM v")
    assert result["allowed"] and {o["table"] for o in result["objects"]} == {"v", "data.parquet"}


def test_replacement_scan_callback_is_inert_outside_validation(db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db.execute("COPY (SELECT 1 AS x) TO 'data.parquet'")
    assert db.execute("SELECT * FROM 'data.parquet'").fetchall() == [(1,)]
    with db.cursor() as other:
        assert other.execute("SELECT * FROM 'data.parquet'").fetchall() == [(1,)]
    assert not validate(db, "SELECT * FROM 'data.parquet'")["allowed"]
    assert db.execute("SELECT * FROM 'data.parquet'").fetchall() == [(1,)]
    assert validate(db, "SELECT * FROM missing_table")["code"] == "binding"


@pytest.mark.parametrize("name", ["data.csv", "missing.csv", "exists.duckdb", "x.db", "x.ddb", "x.avro",
                                  "x.shp", "x.gpkg", "x.fgb", "data.parquet", "x.json", "x.tsv",
                                  "catalog.data.csv", 'data."csv?"'])
def test_unquoted_file_forms_rejected_before_binding(db, tmp_path, monkeypatch, name):
    (tmp_path / "data.csv").write_text("x\n42\n")
    (tmp_path / "catalog.data.csv").write_text("x\n42\n")
    with duckdb.connect(str(tmp_path / "exists.duckdb")) as local:
        local.execute("CREATE TABLE t(x INT)")
    monkeypatch.chdir(tmp_path)
    result = validate(db, "SELECT * FROM " + name)
    assert result["code"] == "forbidden" and result["error_message"] == "", result
    assert result["violations"][0]["rule"] == "replacement_scan"


def test_qualified_file_name_is_not_cte_exempt(db):
    assert validate(db, 'WITH "data.csv" AS (SELECT 1) SELECT * FROM "data.csv"')["allowed"]
    result = validate(db, "WITH csv AS (SELECT 1) SELECT * FROM data.csv")
    assert result["code"] == "forbidden" and result["violations"][0]["rule"] == "replacement_scan"


@pytest.mark.parametrize("name", ["duckdb_views", "duckdb_tables", "duckdb_columns", "duckdb_logs",
                                  "sqlite_master", "information_schema.tables"])
def test_internal_views_require_explicit_permission(db, name):
    for options in [{}, {"allowed_tables": [{"catalog": "*", "schema": "*", "table": "*"}]}]:
        result = validate(db, "SELECT * FROM " + name, options)
        assert result["code"] == "forbidden" and result["error_message"] == "", result
        assert "internal_object" in {v["rule"] for v in result["violations"]}


def test_internal_view_explicit_permission_intersects_other_policies(db):
    table = {"catalog": "SYSTEM", "schema": "MAIN", "table": "DuckDB_Tables"}
    options = {"allowed_tables": [table]}
    configure(db, options)
    result = validate(db, "SELECT * FROM duckdb_tables", options)
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "duckdb_tables"
    assert not validate(db, "SELECT * FROM duckdb_views", options)["allowed"]
    assert not validate(db, "SELECT * FROM duckdb_tables", {"allowed_tables": [{**table, "catalog": "memory"}]})["allowed"]
    assert not validate(db, "SELECT * FROM duckdb_tables", {
        "allowed_tables": [{"schema": "main", "table": "duckdb_tables"}]
    })["allowed"]


def test_object_identifiers_are_ascii_case_insensitive(db):
    db.execute("CREATE SCHEMA Reporting; CREATE TABLE Reporting.Orders(a INT); CREATE TABLE t(x INT)")
    assert validate(db, "SELECT * FROM REPORTING.ORDERS", {"allowed_tables": [{"catalog": "*", "schema": "reporting", "table": "*"}]})["allowed"]
    assert validate(db, "SELECT * FROM MEMORY.main.t", {"allowed_tables": [{"catalog": "memory", "schema": "*", "table": "*"}]})["allowed"]
    db.execute("CREATE MACRO local_abs(x) AS abs(x)")
    configure(db, {"allowed_functions": ["local_abs"]})
    assert validate(db, "SELECT MEMORY.main.local_abs(-1)", {
        "allowed_tables": [], "allowed_functions": ["local_abs"]
    })["allowed"]
    for catalog in [None, "MeMoRy"]:
        options = {"allowed_tables": [{"catalog": catalog, "schema": "REPORTING", "table": "orders"}]}
        assert validate(db, "SELECT * FROM reporting.orders", options)["allowed"]
    result = validate(db, "SELECT * FROM reporting.orders", {"allowed_tables": []})
    assert result["violations"][0]["schema"] == "Reporting"
    assert result["violations"][0]["table"] == "Orders"


@pytest.mark.parametrize("sql", ["", "  ", "-- comment", "/* comment */", "; ;"])
def test_empty_sql_is_invalid_input(db, sql):
    result = validate(db, sql)
    assert result["code"] == "invalid_input" and not result["allowed"]
    assert result["error_message"] == "SQL contains no statements"
    assert result["violations"] == []


def test_validation_uses_connection_parser_options(db):
    db.execute("SET max_expression_depth=10")
    sql = "SELECT " + "abs(" * 20 + "1" + ")" * 20
    with pytest.raises(duckdb.ParserException):
        db.execute(sql)
    assert validate(db, sql)["code"] == "parser"
    db.execute("SET max_expression_depth=1000; SET preserve_identifier_case=false")
    result = validate(db, 'SELECT * FROM MISSING', {"allowed_tables": []})
    assert 'missing' in result["error_message"] and 'MISSING' not in result["error_message"]


@pytest.mark.parametrize("sql", ["SELECT list_transform([1, 2], lambda x: x + 1)",
                                  "SELECT * FROM (VALUES (1)) a CROSS JOIN (VALUES (2)) b"])
def test_latest_ast_serialization(db, sql):
    db.execute(sql).fetchall()
    result = validate(db, sql)
    assert result["allowed"], result


@pytest.mark.parametrize("name", ["csv", "json", "db", "gz"])
def test_qualified_suffix_catalog_table_requires_file_opt_in(db, name):
    db.execute(f'CREATE TABLE main."{name}"(x INT)')
    assert validate(db, f'SELECT * FROM "{name}"')["allowed"]
    for sql in [f"SELECT * FROM main.{name}", f'SELECT * FROM "main"."{name}"']:
        result = validate(db, sql)
        assert result["code"] == "forbidden" and result["error_message"] == ""
        assert result["violations"][0]["rule"] == "replacement_scan"
        configure(db, {"allow_replacement_scans": True})
        assert validate(db, sql, {"allow_replacement_scans": True})["allowed"]
        assert not validate(db, sql, {"allow_replacement_scans": True, "allowed_tables": []})["allowed"]
        configure(db)


def test_internal_dependency_of_trusted_view_requires_opt_in(db):
    db.execute("CREATE VIEW my_tables AS SELECT table_name FROM duckdb_tables")
    assert validate(db, "SELECT * FROM my_tables")["violations"][0]["rule"] == "internal_object"
    options = {"allowed_tables": [{"schema": "main", "table": "my_tables"},
                                  {"catalog": "system", "schema": "main", "table": "duckdb_tables"}]}
    configure(db, options)
    result = validate(db, "SELECT * FROM my_tables", options)
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "duckdb_tables"
