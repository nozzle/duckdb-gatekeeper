"""Regression probes for deny decisions, actual binding, and policy confusion."""
import json

import pytest

from test_binding import validate
from test_gatekeeper import db
from typed_helpers import configure


@pytest.mark.parametrize("sql,options", [
    ("SELECT * FROM range(0,10,0)", {}),
    ("SELECT * FROM range(NULL)", {}),
    ("SELECT * FROM read_parquet('missing-redteam-file.parquet')", {"allowed_functions": ["read_parquet"]}),
    ("SELECT * FROM range(3) t(a,b)", {}),
    ("SELECT * FROM read_csv([])", {"allowed_functions": ["read_csv"]}),
    ("SELECT * FROM read_csv('missing-file',delim='too long')", {"allowed_functions": ["read_csv"]}),
    ("SELECT (SELECT missing FROM range(1))", {}),
])
def test_binding_errors_never_allow(db, sql, options):
    result = validate(db, sql, options)
    if result["code"] != "ok":
        assert result["allowed"] is False, result


@pytest.fixture
def catalog(db):
    db.execute("""CREATE SCHEMA allowed; CREATE SCHEMA secret;
        CREATE TABLE allowed.t AS SELECT 1 AS x;
        CREATE TABLE secret.t AS SELECT 2 AS x;
        CREATE VIEW allowed.v AS SELECT * FROM secret.t;
        CREATE MACRO secret_scalar() AS (SELECT x FROM secret.t);
        CREATE MACRO secret_table() AS TABLE SELECT * FROM secret.t;
        CREATE VIEW allowed.nested_v AS SELECT * FROM allowed.v;
        CREATE MACRO trusted_abs(x) AS abs(x);
        CREATE SEQUENCE secret.sequence;""")
    return db


@pytest.mark.parametrize("sql", [
    "SELECT * FROM secret.t",
    "SELECT * FROM secret.t LIMIT 0",
    "SELECT * FROM secret.t WHERE false",
    "SELECT 1 WHERE EXISTS (SELECT * FROM secret.t)",
    "SELECT (SELECT x FROM secret.t)",
    "SELECT * FROM allowed.t ORDER BY (SELECT x FROM secret.t)",
    "SELECT * FROM allowed.t LIMIT (SELECT x FROM secret.t)",
    "SELECT sum(x) FILTER (WHERE x IN (SELECT x FROM secret.t)) FROM allowed.t",
    "SELECT lag(x, (SELECT x FROM secret.t)) OVER () FROM allowed.t",
    "SELECT * FROM allowed.t JOIN LATERAL (SELECT * FROM secret.t) b ON true",
    "SELECT * FROM allowed.t UNION ALL SELECT * FROM secret.t",
    "WITH t AS (SELECT * FROM secret.t) SELECT * FROM t",
    "WITH t AS MATERIALIZED (SELECT * FROM secret.t) SELECT * FROM t",
    "WITH t AS NOT MATERIALIZED (SELECT * FROM secret.t) SELECT * FROM t",
    "SELECT * FROM allowed.v",
    "SELECT * FROM allowed.nested_v",
    "SELECT secret_scalar()",
    "SELECT * FROM secret_table()",
    "DESCRIBE secret.t",
    "SUMMARIZE secret.t",
])
def test_hidden_table_references(catalog, sql):
    options = {"allowed_tables": [{"catalog": "*", "schema": "allowed", "table": "*"}], "allowed_functions": ["secret_scalar", "secret_table"]}
    result = validate(catalog, sql, options)
    assert not result["allowed"], (sql, result)
    assert result["code"] == "forbidden", (sql, result)


@pytest.mark.parametrize("sql", [
    "WITH t AS (SELECT 1) SELECT * FROM secret.t",
    "WITH t AS (SELECT 1) SELECT * FROM allowed.t WHERE EXISTS (SELECT * FROM secret.t)",
    "WITH RECURSIVE t AS (SELECT * FROM secret.t UNION ALL SELECT x+1 FROM t WHERE x<3) SELECT * FROM t",
    "WITH RECURSIVE t AS (SELECT 1 x UNION ALL SELECT secret.t.x FROM t JOIN secret.t ON true) SELECT * FROM t",
    "WITH a AS (SELECT * FROM b), b AS (SELECT 1) SELECT * FROM a",
    "WITH t AS (SELECT * FROM t) SELECT * FROM t",
])
def test_cte_binding_scope(catalog, sql):
    catalog.execute("SET schema='secret'; CREATE TABLE secret.b AS SELECT 3 x")
    result = validate(catalog, sql, {"allowed_tables": [{"catalog": "*", "schema": "allowed", "table": "*"}]})
    assert not result["allowed"], (sql, result)


@pytest.mark.parametrize("expression", [
    "md5('x')", "md5(x) OVER ()", "CASE WHEN false THEN md5('x') ELSE '' END",
    "list_transform(['x'], lambda y: md5(y))", "(SELECT md5('x'))",
    "list(x ORDER BY md5(x::VARCHAR))", "coalesce(NULL,md5('x'))",
    "sum(x) FILTER (WHERE md5('x')='x')", "lag(x, 1, length(md5('x'))) OVER ()",
])
def test_function_hidden_positions(catalog, expression):
    result = validate(catalog, f"SELECT {expression} FROM allowed.t", {"blocked_functions": ["md5"]})
    assert not result["allowed"], result
    assert result["code"] == "forbidden"
    assert any(v["function_name"]=="md5" for v in result["violations"])


@pytest.mark.parametrize("options", [
    '{"blocked_functions":["md5"],"blocked_functions":[]}',
    '{"blocked_functions":["md5"],"blocked_\\u0066unctions":[]}',
    '{"allowed_tables":[{"schema":"allowed","table":"t","table":"other"}]}',
    '{"limits":{"max_statements":1,"max_statements":2}}',
    '{"limits":{"max_statements":1.0}}',
    '{"limits":{"max_statements":-1}}',
    '{"limits":{"max_statements":true}}',
    '{"limits":{"max_ast_bytes":18446744073709551616}}',
    '{"resolve_objects":null}',
    '{"allowed_catalogs":[null]}',
    '{"allowed_functions":[{"name":"sum"}]}',
    '{"allow_dynamic_sql":1}',
    '{"CHECK_FUNCTIONS":false}',
    '{} {}',
    '{"check_functions":false} trailing',
])
def test_policy_parser_confusion(db, options):
    import duckdb
    with pytest.raises(duckdb.BinderException, match="named typed arguments"):
        db.execute("SELECT gatekeeper_validate('SELECT 1',?)", [options])


def test_preflight_denies_before_reader_binding(db):
    sql = "SELECT * FROM read_parquet('missing-gatekeeper-test.parquet')"
    result = validate(db, sql)
    assert result["code"] == "forbidden" and not result["error_message"]
    configure(db, {"allowed_functions": ["read_parquet"]})
    result = validate(db, sql, {"allowed_functions": ["read_parquet"]})
    assert not result["allowed"] and result["code"] == "binding"


def test_request_cannot_opt_out_of_ceiling(catalog):
    configure(catalog,{"blocked_functions":["md5"],"allowed_tables":[{"catalog":"*","schema":"allowed","table":"*"}]})
    assert not validate(catalog, "SELECT md5('x')", {"blocked_functions": []})["allowed"]
    assert not validate(catalog, "SELECT md5('x')")["allowed"]
    assert not validate(catalog, "SELECT * FROM secret.t", {"allowed_tables": [{"catalog": "*", "schema": "secret", "table": "*"}]})["allowed"]
    assert not validate(catalog, "SELECT * FROM secret.t")["allowed"]


def test_catalog_changes_rechecked(catalog):
    catalog.execute("CREATE VIEW allowed.changing AS SELECT * FROM allowed.t")
    catalog.execute("PREPARE validation AS SELECT gatekeeper_validate('SELECT * FROM allowed.changing',allowed_tables := [{catalog:'*',schema:'allowed','table':'*'}])")
    assert catalog.execute("EXECUTE validation").fetchone()[0]["allowed"]
    catalog.execute("CREATE OR REPLACE VIEW allowed.changing AS SELECT * FROM secret.t")
    assert not catalog.execute("EXECUTE validation").fetchone()[0]["allowed"]


def test_search_path_and_temp_shadowing(catalog):
    catalog.execute("SET schema='allowed'")
    options = {"allowed_tables": [{"catalog": "*", "schema": "allowed", "table": "*"}]}
    assert validate(catalog, "SELECT * FROM t", options)["allowed"]
    catalog.execute("SET schema='secret'")
    assert not validate(catalog, "SELECT * FROM t", options)["allowed"]
    catalog.execute("CREATE TEMP TABLE t(x INT)")
    assert not validate(catalog, "SELECT * FROM t", {"allowed_tables": [{"catalog": "memory", "schema": "*", "table": "*"}]})["allowed"]
    assert validate(catalog, "SELECT * FROM t", {"allowed_tables": [{"catalog": "temp", "schema": "main", "table": "*"}]})["allowed"]


def test_quoted_names_and_exact_catalog(db):
    db.execute('ATTACH \':memory:\' AS "lake.one"; CREATE SCHEMA "lake.one"."report.ing"; CREATE TABLE "lake.one"."report.ing"."ord\'ers"(x INT)')
    sql = 'SELECT * FROM "lake.one"."report.ing"."ord\'ers"'
    options = {"allowed_tables": [{"catalog": "lake.one", "schema": "report.ing", "table": "ord'ers"}]}
    assert validate(db, sql, options)["allowed"]
    assert not validate(db, sql, {"allowed_tables": [{"catalog": "lake", "schema": "one.report.ing", "table": "ord'ers"}]})["allowed"]


def test_trusted_implementation_is_not_caller_code(catalog):
    configure(catalog, {"allowed_functions": ["trusted_abs"]})
    options = {"allowed_functions": ["trusted_abs"], "blocked_functions": ["abs"]}
    assert validate(catalog, "SELECT trusted_abs(-1)", {"allowed_functions": ["trusted_abs"]})["allowed"]
    assert not validate(catalog, "SELECT trusted_abs(-1)", options)["allowed"]
    assert not validate(catalog, "SELECT abs(-1)", options)["allowed"]


def test_validation_cannot_execute_configuration(db):
    result = validate(db, "SELECT gatekeeper_configure('{}')")
    assert not result["allowed"] and result["code"] == "forbidden"
    assert configure(db) is True


def test_mixed_batch_rejected_before_binding(catalog):
    configure(catalog, {"max_statements": 2})
    sql = "SELECT * FROM missing_file_reader(); DROP TABLE allowed.t"
    result = validate(catalog, sql, {"max_statements": 2, "allowed_functions": ["missing_file_reader"]})
    assert not result["allowed"] and result["code"] == "unsupported"
    assert catalog.execute("SELECT * FROM allowed.t").fetchone() == (1,)


@pytest.mark.parametrize("sql", [
    "SELECT 1; /* harmless */ DELETE FROM t RETURNING *",
    "SELECT 1; -- comment\n COPY t TO 'out.csv'",
    "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
    "WITH d AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM d",
    "WITH d AS (UPDATE t SET x=1 RETURNING *) SELECT * FROM d",
])
def test_write_smuggling(db, sql):
    configure(db, {"max_statements": 10})
    result = validate(db, sql, {"max_statements": 10})
    assert not result["allowed"]
    assert result["code"] in {"parser", "unsupported"}


@pytest.mark.parametrize("sql", [
    "SELECT * FROM main.query('SELECT * FROM secret.t')",
    "SELECT * FROM query_table('secret.t')",
    "SELECT * FROM json_execute_serialized_sql('{}')",
    "SELECT system.main.json_serialize_plan('SELECT * FROM secret.t')",
])
def test_dynamic_sql_independent_of_allowlist(catalog, sql):
    options = {"allowed_functions": ["query", "query_table", "json_execute_serialized_sql", "json_serialize_plan"]}
    configure(catalog, options)
    result = validate(catalog, sql, options)
    assert not result["allowed"] and result["code"] == "forbidden"
