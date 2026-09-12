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
    "check_functions := 'false'", "check_functions := 1", "max_statements := 1.5",
    "allowed_functions := 'sum'", "allowed_functions := [1,2]", "allowed_tables := [1]",
    "allowed_tables := ['main.t']",
    "blocked_functions := [], blocked_functions := ['md5']",
])
def test_rejected_signatures(db,args):
    with pytest.raises(duckdb.Error):
        db.execute("SELECT gatekeeper_validate('SELECT 1'," + args + ")")


@pytest.mark.parametrize("options", [
    {"blocked_functions":None}, {"blocked_functions":[None]}, {"blocked_functions":[""]},
    {"allowed_tables":[None]}, {"allowed_tables":[{"table":"t"}]}, {"allowed_tables":[{"schema":"main","table":"t","extra":"x"}]},
    {"max_statements":0}, {"max_ast_nodes":-1},
])
def test_invalid_typed_values(db,options):
    result = validate(db,"SELECT 1", options)
    assert not result["allowed"] and result["code"] == "invalid_input", result


def test_configure_replacement_and_independent_limits(db):
    assert configure(db,{"blocked_functions":["md5"],"max_statements":2})
    assert validate(db,"SELECT 1; SELECT 2", {"max_ast_depth":100})["allowed"]
    assert not validate(db,"SELECT md5('x')")["allowed"]
    assert validate(db,"SELECT md5('x')", {"blocked_functions":[]})["allowed"]
    with pytest.raises(duckdb.Error,match="already configured"):
        configure(db)


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
    result=validate(db,"SELECT 1",{"max_ast_nodes":1})
    assert result["code"]=="forbidden" and result["violations"][0]["rule"]=="limit"


def test_file_backed_view_requires_own_permission(db,tmp_path):
    path=str(tmp_path/"backing.parquet").replace("'","''")
    db.execute(f"COPY (SELECT 42 AS x) TO '{path}' (FORMAT PARQUET)")
    db.execute(f"CREATE VIEW v AS SELECT * FROM read_parquet('{path}')")
    assert not validate(db,"SELECT * FROM v",{"allowed_tables":[]})["allowed"]
    assert validate(db,"SELECT * FROM v",{"allowed_tables":[{"schema":"main","table":"v"}],"allow_table_functions":False})["allowed"]


def test_view_and_underlying_table_must_both_pass(db):
    db.execute("CREATE TABLE t(x INT); CREATE VIEW v AS SELECT * FROM t")
    table={"schema":"main","table":"t"}
    view={"schema":"main","table":"v"}
    assert not validate(db,"SELECT * FROM v",{"allowed_tables":[view]})["allowed"]
    assert not validate(db,"SELECT * FROM v",{"allowed_tables":[table]})["allowed"]
    assert validate(db,"SELECT * FROM v",{"allowed_tables":[view,table]})["allowed"]


def test_dynamic_table_lookup_keeps_object_policy(db):
    db.execute("CREATE TABLE secret(x INT)")
    options={"allow_dynamic_sql":True,"allowed_functions":["query_table","query"],"allowed_tables":[]}
    for sql in ["SELECT * FROM query_table('secret')", "SELECT * FROM query('SELECT * FROM secret')"]:
        result=validate(db,sql,options)
        assert not result["allowed"], (sql,result)


def test_python_replacement_scan_rejected(db):
    # A relation replacement scan is local and needs no optional pandas dependency.
    db.execute("SET threads=1")
    host_data=db.sql("SELECT 1 AS x")
    assert db.execute("SELECT * FROM host_data").fetchone()==(1,)
    result=db.execute("SELECT gatekeeper_validate('SELECT * FROM host_data', allowed_tables := [])").fetchone()[0]
    assert not result["allowed"] and result["code"]=="unsupported", result
    assert result["violations"][0]["rule"]=="replacement_scan"


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
    assert result["violations"][0]["rule"] == "file_table"


def test_file_name_opt_in_only_authorizes_catalog_object(db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db.execute('CREATE TABLE "data.parquet"(x INT)')
    assert not validate(db, 'SELECT * FROM "data.parquet"')["allowed"]
    assert validate(db, 'SELECT * FROM "data.parquet"', {"allow_file_table_references": True})["allowed"]
    result = validate(db, "SELECT * FROM 'missing.duckdb'", {"allow_file_table_references": True})
    assert not result["allowed"] and result["code"] == "binding"
