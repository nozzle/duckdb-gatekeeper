import duckdb
import pytest

from support.artifact import by_parser
from support.enforcement import engine_code
from support.typed_helpers import configure, validate


def test_named_prepared_options_and_result_columns(db):
    result = db.execute("SELECT * FROM gatekeeper_validate(?, blocked_functions := ?)", ["SELECT md5('x')", ["md5"]])
    assert [column[0] for column in result.description] == [
        "allowed", "code", "violations", "error_type", "error_message", "position", "objects", "functions"
    ]
    rows = result.fetchall()
    assert len(rows) == 1
    assert rows[0][0] is False and rows[0][1] == "forbidden"
    assert rows[0][2][0]["function_name"] == "md5"


def test_table_projection_filter_and_join(db):
    assert db.execute("SELECT code, allowed FROM gatekeeper_validate('SELECT 1')").fetchall() == [("ok", True)]
    assert db.execute("SELECT * FROM gatekeeper_validate('DROP TABLE t') WHERE allowed").fetchall() == []
    assert db.execute("SELECT count(*) FROM gatekeeper_validate('SELECT 1')").fetchone() == (1,)
    assert db.execute("""SELECT i, allowed FROM range(3) t(i)
        CROSS JOIN gatekeeper_validate('SELECT 1') ORDER BY i""").fetchall() == [(0, True), (1, True), (2, True)]


@pytest.mark.parametrize("argument", ["sql_text", "'SELECT 1', blocked_functions := blocks"])
def test_lateral_arguments_rejected(db, argument):
    with pytest.raises(duckdb.BinderException):
        db.execute("SELECT v.* FROM (VALUES ('SELECT 1', ['md5'])) q(sql_text, blocks), "
                   "LATERAL gatekeeper_validate(" + argument + ") v")


def test_validation_requires_table_function_syntax(db):
    with pytest.raises(duckdb.BinderException, match="table function"):
        db.execute("SELECT gatekeeper_validate('SELECT 1')")


@pytest.mark.parametrize("name", ["blocked_functions", "allowed_tables", "blocked_tables"])
@pytest.mark.parametrize("value", ["[NULL]", "[NULL]::DOUBLE[]"])
def test_all_null_lists_return_invalid_input(db, name, value):
    assert db.execute(f"SELECT code FROM gatekeeper_validate('SELECT 1', {name} := {value})").fetchall() == [
        ("invalid_input",)
    ]


@pytest.mark.parametrize("sql,code", [("SELECT 1", "ok"), ("DROP TABLE t", "unsupported"),
                                     ("SELECT md5('x')", "forbidden"), ("SELECT * FROM", "parser"),
                                     ("SELECT * FROM missing", "binding"), (None, "invalid_input")])
def test_exactly_one_row_for_each_outcome(db, sql, code):
    rows = db.execute("SELECT allowed, code FROM gatekeeper_validate(?, blocked_functions := ['md5'])",
                      [sql]).fetchall()
    assert rows == [(code == "ok", code)]


def test_prepared_parameters_rebind_sql_and_options(db):
    db.execute("PREPARE validation AS SELECT allowed, code FROM gatekeeper_validate($1, blocked_functions := $2)")
    for args, expected in [("'SELECT md5(''x'')', ['md5']", (False, "forbidden")),
                           ("'SELECT md5(''x'')', []", (True, "ok")),
                           ("NULL, []", (False, "invalid_input")),
                           ("'DROP TABLE t', []", (False, "unsupported"))]:
        assert db.execute("EXECUTE validation(" + args + ")").fetchall() == [expected]


def test_preparing_does_not_validate_submitted_sql(db):
    db.execute("PREPARE validation AS SELECT code FROM gatekeeper_validate('SELECT * FROM later')")
    assert db.execute("EXECUTE validation").fetchall() == [("binding",)]
    db.execute("CREATE TABLE later(i INT)")
    assert db.execute("EXECUTE validation").fetchall() == [("ok",)]
    db.execute("DROP TABLE later")
    assert db.execute("EXECUTE validation").fetchall() == [("binding",)]


@pytest.mark.parametrize("args", [
    "unknown := true", "use_default_functions := 'false'", "use_default_functions := 1",
    "allowed_functions := 'sum'", "allowed_functions := [1,2]", "allowed_tables := [1]",
    "allowed_tables := ['main.t']",
    "blocked_functions := [], blocked_functions := ['md5']",
    "blocked_tables := [1]", "blocked_tables := ['main.t']",
])
def test_rejected_signatures(db,args):
    with pytest.raises(duckdb.Error):
        db.execute("SELECT * FROM gatekeeper_validate('SELECT 1'," + args + ")")
    with pytest.raises(duckdb.Error):
        db.execute("CALL gatekeeper_configure(" + args.replace("'SELECT 1',", "") + ")")


@pytest.mark.parametrize("options", [
    {"blocked_functions":None}, {"blocked_functions":[None]}, {"blocked_functions":[""]},
    {"allowed_tables":[None]}, {"allowed_tables":[{"table":"t"}]}, {"allowed_tables":[{"schema":"main","table":"t","extra":"x"}]},
])
def test_invalid_typed_values(db,options):
    result = validate(db,"SELECT 1", options)
    assert not result["allowed"] and result["code"] == "invalid_input", result


def test_configure_replacement_and_independent_options(db):
    assert configure(db,{"blocked_functions":["md5"]})
    assert validate(db,"SELECT 1", {"use_default_functions":False})["allowed"]
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
    # The parser's own error location: the default parser reports the end of the input, the PEG parser the
    # token it could not continue from.
    assert result["position"]==by_parser(postgres=13, peg=9) and result["error_type"]=="parser"


def test_file_backed_view_requires_own_permission(db,tmp_path):
    path=str(tmp_path/"backing.parquet").replace("'","''")
    db.execute(f"COPY (SELECT 42 AS x) TO '{path}' (FORMAT PARQUET)")
    db.execute(f"CREATE VIEW v AS SELECT * FROM read_parquet('{path}')")
    assert not validate(db,"SELECT * FROM v",{"allowed_tables":[]})["allowed"]
    assert validate(db,"SELECT * FROM v",{"allowed_tables":[{"schema":"main","table":"v"}]})["allowed"]
    result = validate(db, f"SELECT * FROM read_parquet('{path}')")
    assert result["code"] == "forbidden" and result["violations"][0]["rule"] == "function"
    # The view's reader is the view's: neither the allowlist nor a block on it reaches into the body.
    assert validate(db, "SELECT * FROM v", {"blocked_functions": ["read_parquet"]})["allowed"]


def test_view_is_authorized_by_its_own_identity(db):
    # The view the caller names must pass; the table its body reads is the view's own and appears as evidence.
    # The caller's own reference to that table, next to the view, is still the caller's.
    db.execute("CREATE TABLE t(x INT); CREATE VIEW v AS SELECT * FROM t")
    table={"schema":"main","table":"t"}
    view={"schema":"main","table":"v"}
    result = validate(db,"SELECT * FROM v",{"allowed_tables":[view]})
    assert result["allowed"] and [(o["table"], o["type"]) for o in result["objects"]] == [("t", "table"), ("v", "view")]
    assert not validate(db,"SELECT * FROM v",{"allowed_tables":[table]})["allowed"]
    assert validate(db,"SELECT * FROM v",{"allowed_tables":[view,table]})["allowed"]
    denied = validate(db,"SELECT * FROM v JOIN t USING (x)",{"allowed_tables":[view]})
    assert denied["code"] == "forbidden" and denied["violations"][0]["table"] == "t", denied
    assert validate(db,"SELECT * FROM v JOIN t USING (x)",{"allowed_tables":[view,table]})["allowed"]


def test_dynamic_table_lookup_keeps_object_policy(db):
    db.execute("CREATE TABLE secret(x INT)")
    options={"allowed_functions":["query_table","query"],"allowed_tables":[]}
    for sql in ["SELECT * FROM query_table('secret')", "SELECT * FROM query('SELECT * FROM secret')"]:
        result=validate(db,sql,options)
        assert not result["allowed"], (sql,result)


def test_python_replacement_scan_rejected(db):
    # A relation replacement scan is local and needs no optional pandas dependency. It resolves to a
    # subquery, not a table function, so it cannot be authorized through reader permissions.
    db.execute("SET threads=1")
    host_data=db.sql("SELECT 1 AS x")
    assert db.execute("SELECT * FROM host_data").fetchone()==(1,)
    # The Python scan resolves names in the calling frame, so validate from this frame directly.
    for options in ["allowed_tables := []", "blocked_tables := []"]:
        db.execute("CALL gatekeeper_configure(" + options + ")")
        cursor = db.execute("SELECT * FROM gatekeeper_validate('SELECT * FROM host_data', " + options + ")")
        result = dict(zip((column[0] for column in cursor.description), cursor.fetchone()))
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
    result=validate(db,"SELECT 1",{"blocked_functions":[None]})
    assert not result["allowed"] and result["code"]=="invalid_input", result


@pytest.mark.parametrize("name", ["exists.duckdb", "missing.duckdb", "x.db", "x.ddb",
                                  "data.parquet?", "nope.parquet?", "x.json?", "x.jsonl?", "x.ndjson?", "x.csv?", "x.tsv?"])
def test_relative_file_forms_rejected_before_binding(db, tmp_path, monkeypatch, name):
    with duckdb.connect(str(tmp_path / "exists.duckdb")) as local:
        local.execute("CREATE TABLE t(x INT)")
    (tmp_path / "data.parquetx").write_bytes(b"not parquet")
    monkeypatch.chdir(tmp_path)
    result = validate(db, "SELECT * FROM '" + name + "'")
    assert result["code"] == "forbidden" and result["error_message"] == "", result
    assert result["violations"][0]["rule"] == "function"


def test_file_shaped_catalog_name_uses_table_policy(db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db.execute('CREATE TABLE "data.parquet"(x INT)')
    result = validate(db, 'SELECT * FROM "data.parquet"')
    assert result["allowed"] and result["objects"][0]["type"] == "table"
    assert not validate(db, 'SELECT * FROM "data.parquet"', {"allowed_tables": []})["allowed"]
    assert not validate(db, 'SELECT * FROM "data.parquet"', {
        "blocked_tables": [{"schema": "main", "table": "data.parquet"}]
    })["allowed"]
    result = validate(db, "SELECT * FROM 'missing.duckdb'")
    assert not result["allowed"] and result["code"] == "forbidden"
    assert result["violations"][0]["function_name"] == "read_duckdb"


def test_replacement_scan_authorizes_resolved_reader_without_prebind_io(db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db.execute("COPY (SELECT 1 AS x) TO 'data.parquet'")
    (tmp_path / "data.csv").write_text("x\n42\n")
    # Reader not admitted: denied at the callback, so a missing path never binds.
    for name in ["data.parquet", "/does/not/exist.parquet", "data.csv", "s3://bucket/key.parquet"]:
        result = validate(db, f"SELECT * FROM '{name}'")
        assert result["code"] == "forbidden" and result["error_message"] == "", (name, result)
        violation = result["violations"][0]
        assert violation["rule"] == "function" and violation["table"] == name
        assert violation["function_name"] in {"read_parquet", "read_csv_auto"}
    configure(db, {"allowed_functions": ["parquet_scan", "read_csv_auto"]})
    for name, function in [("data.parquet", "parquet_scan"), ("data.csv", "read_csv_auto")]:
        result = validate(db, f"SELECT * FROM '{name}'")
        assert result["allowed"], (name, result)
        assert result["objects"] == [{"catalog": "", "schema": "", "table": name, "type": "replacement"}]
        assert [f["name"] for f in result["functions"]] == [function]
    # An admitted reader still surfaces real binding errors for missing files.
    assert validate(db, "SELECT * FROM '/does/not/exist.parquet'")["code"] == "binding"
    # Requests can narrow reader permissions but cannot escape the global allowlist.
    assert not validate(db, "SELECT * FROM 'data.parquet'", {
        "use_default_functions": False, "allowed_functions": []
    })["allowed"]
    assert not validate(db, "SELECT * FROM 'data.parquet'", {"blocked_functions": ["parquet_scan"]})["allowed"]
    configure(db)
    result = validate(db, "SELECT * FROM 'data.parquet'", {"allowed_functions": ["read_parquet"]})
    assert result["code"] == "forbidden" and result["violations"][0]["rule"] == "function"
    # allowed_tables governs catalog objects, not reader capabilities, matching range().
    configure(db, {"allowed_functions": ["parquet_scan"], "allowed_tables": [],
                   "blocked_tables": [{"catalog": "*", "schema": "*", "table": "*"}]})
    assert validate(db, "SELECT * FROM 'data.parquet'")["allowed"]


def test_replacement_scan_inside_view_is_a_trusted_expansion(db, tmp_path, monkeypatch):
    # FROM 'file' inside a host-defined view is that view's own reader, treated like an explicit
    # read_parquet(...) in the same body: outside function policy altogether, allowlist and blocks alike.
    monkeypatch.chdir(tmp_path)
    db.execute("COPY (SELECT 1 AS x) TO 'data.parquet'; CREATE VIEW v AS SELECT * FROM 'data.parquet'")
    result = validate(db, "SELECT * FROM v")
    assert result["allowed"] and {o["table"] for o in result["objects"]} == {"v", "data.parquet"}
    assert {(o["table"], o["type"]) for o in result["objects"]} == {("v", "view"), ("data.parquet", "replacement")}
    # A block under either Parquet alias, in either layer, does not reach into the body.
    for blocked in ["read_parquet", "parquet_scan"]:
        assert validate(db, "SELECT * FROM v", {"blocked_functions": [blocked]})["allowed"]
    configure(db, {"blocked_functions": ["read_parquet"]})
    assert validate(db, "SELECT * FROM v")["allowed"]
    configure(db, {})
    # The view still needs its own permission; the reader's exemption does not grant the object.
    assert not validate(db, "SELECT * FROM v", {"allowed_tables": []})["allowed"]
    # Nesting keeps the trust: a view over the view, a CTE or subquery inside the body, a table macro body.
    db.execute("CREATE VIEW outer_v AS WITH c AS (SELECT * FROM (SELECT * FROM 'data.parquet')) SELECT c.x FROM c, v")
    assert validate(db, "SELECT * FROM outer_v", {"blocked_functions": ["read_parquet"]})["allowed"]
    db.execute("CREATE MACRO m() AS TABLE SELECT * FROM 'data.parquet'")
    assert validate(db, "SELECT * FROM m()")["code"] == "forbidden"  # the macro itself is caller-written
    configure(db, {"allowed_functions": ["m"]})
    assert validate(db, "SELECT * FROM m()")["allowed"]
    assert validate(db, "SELECT * FROM m()", {"blocked_functions": ["read_parquet"]})["allowed"]
    assert validate(db, "SELECT * FROM m()", {"blocked_functions": ["m"]})["code"] == "forbidden"
    configure(db, {})


def test_caller_written_shorthand_still_needs_the_reader(db, tmp_path, monkeypatch):
    # The exemption is by provenance, not by path: every spelling the caller can give a replacement scan is
    # the caller's reader choice and must pass the allowlist, alone or next to a trusted view of the same file.
    monkeypatch.chdir(tmp_path)
    db.execute("COPY (SELECT 1 AS x) TO 'data.parquet'; CREATE VIEW v AS SELECT * FROM 'data.parquet'")
    denied = [
        "SELECT * FROM 'data.parquet'",
        "SELECT * FROM data.parquet",  # unquoted: schema 'data', table 'parquet', same replacement path
        "SELECT * FROM 'DATA.PARQUET'",
        "DESCRIBE 'data.parquet'",
        "WITH c AS (SELECT * FROM 'data.parquet') SELECT * FROM c",
        "SELECT (SELECT count(*) FROM 'data.parquet')",
        "SELECT * FROM v, 'data.parquet'",  # the caller and the view name the same file: the caller's check
        "SELECT * FROM v JOIN 'data.parquet' USING (x)",
        "SELECT * FROM v UNION ALL SELECT * FROM 'data.parquet'",
        "PIVOT 'data.parquet' ON x USING count(*)",
    ]
    for sql in denied:
        result = validate(db, sql)
        assert result["code"] == "forbidden", (sql, result)
        assert result["violations"][0]["rule"] == "function", (sql, result)
        assert result["violations"][0]["function_name"] == "read_parquet", (sql, result)
    # A caller-written name that is a different file does not borrow the view's exemption either.
    db.execute("COPY (SELECT 2 AS x) TO 'other.parquet'")
    result = validate(db, "SELECT * FROM v, 'other.parquet'")
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "read_parquet"
    # Admitting the reader restores every spelling, and the collision case lists both objects. The upper-case
    # spelling is denied by name (provenance is case-folded) but names a file only case-insensitive filesystems
    # have, so once admitted its outcome is the filesystem's: a bind error there is not a denial.
    configure(db, {"allowed_functions": ["parquet_scan"]})
    for sql in denied:
        result = validate(db, sql)
        assert result["allowed"] or (sql == "SELECT * FROM 'DATA.PARQUET'" and result["code"] == "binding"), (sql, result)
    result = validate(db, "SELECT * FROM v, 'data.parquet'")
    assert {o["table"] for o in result["objects"]} == {"v", "data.parquet"}


def test_replacement_scan_callback_is_inert_outside_validation(db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db.execute("COPY (SELECT 1 AS x) TO 'data.parquet'")
    assert db.execute("SELECT * FROM 'data.parquet'").fetchall() == [(1,)]
    with db.cursor() as other:
        assert other.execute("SELECT * FROM 'data.parquet'").fetchall() == [(1,)]
    assert not validate(db, "SELECT * FROM 'data.parquet'")["allowed"]
    assert db.execute("SELECT * FROM 'data.parquet'").fetchall() == [(1,)]
    assert validate(db, "SELECT * FROM missing_table")["code"] == "binding"


@pytest.mark.parametrize("name", ["data.csv", "missing.csv", "exists.duckdb", "x.ddb",
                                  "data.parquet", "x.json", "x.tsv",
                                  "catalog.data.csv", 'data."csv?"'])
def test_unquoted_file_forms_rejected_before_binding(db, tmp_path, monkeypatch, name):
    (tmp_path / "data.csv").write_text("x\n42\n")
    (tmp_path / "catalog.data.csv").write_text("x\n42\n")
    with duckdb.connect(str(tmp_path / "exists.duckdb")) as local:
        local.execute("CREATE TABLE t(x INT)")
    monkeypatch.chdir(tmp_path)
    result = validate(db, "SELECT * FROM " + name)
    assert result["code"] == "forbidden" and result["error_message"] == "", result
    assert result["violations"][0]["rule"] == "function"


def test_qualified_file_name_is_not_cte_exempt(db):
    assert validate(db, 'WITH "data.csv" AS (SELECT 1) SELECT * FROM "data.csv"')["allowed"]
    result = validate(db, "WITH csv AS (SELECT 1) SELECT * FROM data.csv")
    assert result["code"] == "forbidden" and result["violations"][0]["rule"] == "function"


@pytest.mark.parametrize("name", ["x.avro", "x.shp", "x.gpkg", "x.fgb"])
def test_unclaimed_file_names_return_missing_table_without_autoload(db, name):
    result = validate(db, "SELECT * FROM '" + name + "'")
    assert result["code"] == "binding" and not result["allowed"], result
    assert result["objects"] == result["functions"] == []


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


@pytest.mark.parametrize("sql", ["", "  ", "-- comment", "/* comment */", ";", ";;", "; ;"])
def test_empty_sql_is_invalid_input(db, sql):
    result = validate(db, sql)
    assert result["code"] == "invalid_input" and not result["allowed"]
    assert result["error_message"] == "SQL contains no statements"
    assert result["violations"] == []


def test_validation_uses_connection_parser_options(db):
    db.execute("SET max_expression_depth=10")
    sql = "SELECT " + "abs(" * 20 + "1" + ")" * 20
    # The default parser enforces max_expression_depth itself; the PEG parser leaves it to the binder. Either
    # way the validator must fail the text at the same stage the engine does, under the connection's setting.
    with pytest.raises((duckdb.ParserException, duckdb.BinderException)) as engine:
        db.execute(sql)
    assert validate(db, sql)["code"] == engine_code(engine.value)
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
def test_qualified_suffix_catalog_table_uses_table_policy(db, name):
    db.execute(f'CREATE TABLE main."{name}"(x INT)')
    assert validate(db, f'SELECT * FROM "{name}"')["allowed"]
    for sql in [f"SELECT * FROM main.{name}", f'SELECT * FROM "main"."{name}"']:
        assert validate(db, sql)["allowed"]
        assert not validate(db, sql, {"allowed_tables": []})["allowed"]


def test_internal_dependency_of_trusted_view_is_the_views_own(db):
    # The internal duckdb_tables view is the host view's own dependency: allowing the host view admits it, and
    # the never-bind reader behind it is the definition's, not the caller's. The caller's own duckdb_tables, as
    # a view or as the reader, still needs its own permission, next to the host view included.
    db.execute("CREATE VIEW my_tables AS SELECT table_name FROM duckdb_tables")
    assert validate(db, "SELECT * FROM my_tables")["allowed"]
    assert validate(db, "SELECT * FROM duckdb_tables")["violations"][0]["rule"] == "internal_object"
    options = {"allowed_tables": [{"schema": "main", "table": "my_tables"}]}
    configure(db, options)
    result = validate(db, "SELECT * FROM my_tables", options)
    assert result["allowed"] and any(f["name"] == "duckdb_tables" for f in result["functions"]), result
    assert {"catalog": "system", "schema": "main", "table": "duckdb_tables", "type": "view"} in result["objects"], result
    assert validate(db, "SELECT * FROM duckdb_tables", options)["violations"][0]["rule"] == "internal_object"
    assert validate(db, "SELECT * FROM my_tables, duckdb_tables", options)["violations"][0]["rule"] == "internal_object"
    assert validate(db, "SELECT * FROM duckdb_tables()", options)["code"] == "forbidden"
    assert validate(db, "SELECT * FROM my_tables, duckdb_tables()", options)["code"] == "forbidden"
