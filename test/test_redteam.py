"""Regression probes for deny decisions, actual binding, and policy confusion."""

import pytest

from support.artifact import by_engine
from support.typed_helpers import configure, validate


@pytest.mark.parametrize("sql,options", [
    ("SELECT * FROM range(0,10,0)", {}),
    ("SELECT * FROM range(NULL)", {}),
    ("SELECT * FROM read_parquet('missing-redteam-file.parquet')", {"allowed_functions": [{"schema_path": ["*"], "name": "read_parquet"}]}),
    ("SELECT * FROM range(3) t(a,b)", {}),
    ("SELECT * FROM read_csv([])", {"allowed_functions": [{"schema_path": ["*"], "name": "read_csv"}]}),
    ("SELECT * FROM read_csv('missing-file',delim='too long')", {"allowed_functions": [{"schema_path": ["*"], "name": "read_csv"}]}),
    ("SELECT (SELECT missing FROM range(1))", {}),
])
def test_binding_errors_never_allow(db, sql, options):
    result = validate(db, sql, options)
    if result["code"] != "ok":
        assert result["allowed"] is False, result


@pytest.fixture
def split(db):
    """An allowed and a secret schema, with definitions in the first that reach into the second."""
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
    "SELECT * FROM allowed.v, secret.t",
    "SELECT * FROM allowed.nested_v WHERE x IN (SELECT x FROM secret.t)",
    "SELECT secret_scalar() FROM secret.t",
    "SELECT * FROM secret_table(), secret.t",
    "DESCRIBE secret.t",
    "SUMMARIZE secret.t",
])
def test_hidden_table_references(split, sql):
    configure(split, {"allowed_functions": [{"schema_path": ["*"], "name": "secret_scalar"}, {"schema_path": ["*"], "name": "secret_table"}]})
    options = {"allowed_tables": [{"catalog": "*", "schema_path": ["allowed"], "table": "*"}], "allowed_functions": [{"schema_path": ["*"], "name": "secret_scalar"}, {"schema_path": ["*"], "name": "secret_table"}]}
    result = validate(split, sql, options)
    assert not result["allowed"], (sql, result)
    assert result["code"] == "forbidden", (sql, result)


@pytest.mark.parametrize("sql", [
    "SELECT * FROM allowed.v",
    "SELECT * FROM allowed.nested_v",
    "SELECT secret_scalar()",
    "SELECT * FROM secret_table()",
    "SELECT secret_scalar() FROM allowed.v",
    "WITH t AS (SELECT 1 AS x) SELECT * FROM allowed.v",
])
def test_trusted_definitions_are_opaque_to_table_policy(split, sql):
    # The caller may reach secret.t only through a definition the host created and the policy allows: the view,
    # the nested view, the scalar macro's subquery, the table macro's body. What such a definition reads is its
    # own, and is still reported as evidence. A CTE named like the table the view reads is not a reference to it.
    configure(split, {"allowed_functions": [{"schema_path": ["*"], "name": "secret_scalar"}, {"schema_path": ["*"], "name": "secret_table"}]})
    options = {"allowed_tables": [{"catalog": "*", "schema_path": ["allowed"], "table": "*"}]}
    result = validate(split, sql, options)
    assert result["allowed"], (sql, result)
    assert {"catalog": "memory", "schema_path": ["secret"], "table": "t", "type": "table"} in result["objects"], (sql, result)
    assert not validate(split, sql, {"allowed_tables": [], "allowed_functions": []})["allowed"]


@pytest.mark.parametrize("sql", [
    "WITH t AS (SELECT 1) SELECT * FROM secret.t",
    "WITH t AS (SELECT 1) SELECT * FROM allowed.t WHERE EXISTS (SELECT * FROM secret.t)",
    "WITH RECURSIVE t AS (SELECT * FROM secret.t UNION ALL SELECT x+1 FROM t WHERE x<3) SELECT * FROM t",
    "WITH RECURSIVE t AS (SELECT 1 x UNION ALL SELECT secret.t.x FROM t JOIN secret.t ON true) SELECT * FROM t",
    "WITH a AS (SELECT * FROM b), b AS (SELECT 1) SELECT * FROM a",
    "WITH t AS (SELECT * FROM t) SELECT * FROM t",
])
def test_cte_binding_scope(split, sql):
    split.execute("SET schema='secret'; CREATE TABLE secret.b AS SELECT 3 x")
    result = validate(split, sql, {"allowed_tables": [{"catalog": "*", "schema_path": ["allowed"], "table": "*"}]})
    assert not result["allowed"], (sql, result)


@pytest.mark.parametrize("expression", [
    "md5('x')", "md5(x) OVER ()", "CASE WHEN false THEN md5('x') ELSE '' END",
    "list_transform(['x'], lambda y: md5(y))", "(SELECT md5('x'))",
    "list(x ORDER BY md5(x::VARCHAR))", "coalesce(NULL,md5('x'))",
    "sum(x) FILTER (WHERE md5('x')='x')", "lag(x, 1, length(md5('x'))) OVER ()",
])
def test_function_hidden_positions(split, expression):
    result = validate(split, f"SELECT {expression} FROM allowed.t", {"blocked_functions": [{"schema_path":["*"],"name":"md5"}]})
    assert not result["allowed"], result
    assert result["code"] == "forbidden"
    assert any(v["function_name"]=="md5" for v in result["violations"])


@pytest.mark.parametrize("options", [
    "blocked_functions := [{schema_path:['*'],name:'md5'}], BLOCKED_FUNCTIONS := []",
    "allowed_tables := [{schema_path: ['main'], 'table': 't', TABLE: 'other'}]",
])
def test_duplicate_typed_policy_fields(db, options):
    import duckdb
    with pytest.raises(duckdb.Error):
        db.execute("SELECT * FROM gatekeeper_validate('SELECT 1', " + options + ")")


def test_preflight_denies_before_reader_binding(db):
    sql = "SELECT * FROM read_parquet('missing-gatekeeper-test.parquet')"
    result = validate(db, sql)
    assert result["code"] == "forbidden" and not result["error_message"]
    configure(db, {"allowed_functions": [{"schema_path": ["*"], "name": "read_parquet"}]})
    result = validate(db, sql, {"allowed_functions": [{"schema_path": ["*"], "name": "read_parquet"}]})
    assert not result["allowed"] and result["code"] == "binding"


def test_request_cannot_opt_out_of_ceiling(split):
    configure(split,{"blocked_functions":[{"schema_path":["*"],"name":"md5"}],"allowed_tables":[{"catalog":"*","schema_path":["allowed"],"table":"*"}]})
    assert not validate(split, "SELECT md5('x')", {"blocked_functions": []})["allowed"]
    assert not validate(split, "SELECT md5('x')")["allowed"]
    assert not validate(split, "SELECT * FROM secret.t", {"allowed_tables": [{"catalog": "*", "schema_path": ["secret"], "table": "*"}]})["allowed"]
    assert not validate(split, "SELECT * FROM secret.t")["allowed"]


def test_catalog_changes_rechecked(split):
    # Every validation binds against the catalog as it is: the definition behind a name is read again, so the
    # evidence follows a replaced view and the decision follows a dropped one.
    split.execute("CREATE VIEW allowed.changing AS SELECT * FROM allowed.t")
    split.execute("PREPARE validation AS SELECT allowed, list_transform(objects, lambda o: o.schema_path[1] || '.' || o.\"table\") "
                  "FROM gatekeeper_validate('SELECT * FROM allowed.changing',allowed_tables := [{catalog:'*',schema_path:['allowed'],'table':'*'}])")
    assert split.execute("EXECUTE validation").fetchone() == (True, ["allowed.changing", "allowed.t"])
    split.execute("CREATE OR REPLACE VIEW allowed.changing AS SELECT * FROM secret.t")
    assert split.execute("EXECUTE validation").fetchone() == (True, ["allowed.changing", "secret.t"])
    split.execute("DROP VIEW allowed.changing")
    assert split.execute("EXECUTE validation").fetchone() == (False, [])


def test_search_path_and_temp_shadowing(split):
    split.execute("SET schema='allowed'")
    options = {"allowed_tables": [{"catalog": "*", "schema_path": ["allowed"], "table": "*"}]}
    assert validate(split, "SELECT * FROM t", options)["allowed"]
    split.execute("SET schema='secret'")
    assert not validate(split, "SELECT * FROM t", options)["allowed"]
    split.execute("CREATE TEMP TABLE t(x INT)")
    assert not validate(split, "SELECT * FROM t", {"allowed_tables": [{"catalog": "memory", "schema_path": ["*"], "table": "*"}]})["allowed"]
    assert validate(split, "SELECT * FROM t", {"allowed_tables": [{"catalog": "temp", "schema_path": ["main"], "table": "*"}]})["allowed"]


def test_quoted_names_and_exact_catalog(db):
    db.execute('ATTACH \':memory:\' AS "lake.one"; CREATE SCHEMA "lake.one"."report.ing"; CREATE TABLE "lake.one"."report.ing"."ord\'ers"(x INT)')
    sql = 'SELECT * FROM "lake.one"."report.ing"."ord\'ers"'
    options = {"allowed_tables": [{"catalog": "lake.one", "schema_path": ["report.ing"], "table": "ord'ers"}]}
    assert validate(db, sql, options)["allowed"]
    assert not validate(db, sql, {"allowed_tables": [{"catalog": "lake", "schema_path": ["one.report.ing"], "table": "ord'ers"}]})["allowed"]


def test_trusted_implementation_is_not_caller_code(split):
    # The host macro's abs is the macro's: allowing the macro admits its body whatever the caller may not write
    # directly. The caller's own abs stays blocked, alone or next to the macro, and the macro cannot be used to
    # launder a caller-written argument that is itself blocked.
    configure(split, {"allowed_functions": [{"schema_path": ["*"], "name": "trusted_abs"}]})
    options = {"allowed_functions": [{"schema_path": ["*"], "name": "trusted_abs"}], "blocked_functions": [{"schema_path":["*"],"name":"abs"}]}
    assert validate(split, "SELECT trusted_abs(-1)", {"allowed_functions": [{"schema_path": ["*"], "name": "trusted_abs"}]})["allowed"]
    assert validate(split, "SELECT trusted_abs(-1)", options)["allowed"]
    for sql in ["SELECT abs(-1)", "SELECT trusted_abs(-1), abs(-2)", "SELECT trusted_abs(abs(-1))"]:
        result = validate(split, sql, options)
        assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "abs", (sql, result)


def test_validation_cannot_execute_configuration(db):
    result = validate(db, "SELECT gatekeeper_configure('{}')")
    assert not result["allowed"] and result["code"] == "forbidden"
    assert configure(db) is True


def test_mixed_batch_rejected_before_binding(split):
    configure(split, {"allowed_functions": [{"schema_path": ["*"], "name": "missing_file_reader"}]})
    sql = "SELECT * FROM missing_file_reader(); DROP TABLE allowed.t"
    result = validate(split, sql, {"allowed_functions": [{"schema_path": ["*"], "name": "missing_file_reader"}]})
    assert not result["allowed"] and result["code"] == "forbidden"
    assert result["violations"][0]["rule"] == "limit"
    assert result["error_message"] == ""
    assert split.execute("SELECT * FROM allowed.t").fetchone() == (1,)


# DuckDB 1.5's parser rejects data-modifying CTEs; 2.0 parses them into query nodes of their own
# (DELETE_QUERY_NODE, ...), which the grammar does not know and refuses as unsupported.
DML_CTE = by_engine(v1="parser", v2="unsupported")


@pytest.mark.parametrize("sql,code", [
    ("SELECT 1; /* harmless */ DELETE FROM t RETURNING *", "forbidden"),
    ("SELECT 1; -- comment\n COPY t TO 'out.csv'", "forbidden"),
    ("WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", DML_CTE),
    ("WITH d AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM d", DML_CTE),
    ("WITH d AS (UPDATE t SET x=1 RETURNING *) SELECT * FROM d", DML_CTE),
])
def test_write_smuggling(db, sql, code):
    result = validate(db, sql)
    assert not result["allowed"]
    assert result["code"] == code
    if code == "forbidden":
        assert result["violations"][0]["rule"] == "limit"


@pytest.mark.parametrize("sql", ["SELECT * FROM a.b.c.d", "SELECT a.b.c.abs(1)", "SELECT max(x) OVER () FROM a.b.c.d"])
def test_missing_nested_schema_objects_fail_binding(db, sql):
    """2.0 accepts nested names, but these objects do not exist. 1.5 refuses their syntax."""
    db.execute("CREATE TABLE t(x INTEGER)")
    result = validate(db, sql)
    assert not result["allowed"]
    assert result["code"] == by_engine(v1="parser", v2="binding"), result


@pytest.mark.parametrize("sql", [
    "SELECT * FROM main.query('SELECT * FROM secret.t')",
    "SELECT * FROM query_table('secret.t')",
    "SELECT * FROM json_execute_serialized_sql('{}')",
    "SELECT system.main.json_serialize_plan('SELECT * FROM secret.t')",
])
def test_dynamic_sql_independent_of_allowlist(split, sql):
    options = {"allowed_functions": [{"schema_path": ["*"], "name": n} for n in ["query", "query_table", "json_execute_serialized_sql", "json_serialize_plan"]]}
    configure(split, options)
    result = validate(split, sql, options)
    assert not result["allowed"] and result["code"] == "forbidden"
