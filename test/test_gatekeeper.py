import concurrent.futures
import json
import os
from pathlib import Path

import duckdb
import pytest
from typed_helpers import validate as check, configure

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = Path(os.getenv("GATEKEEPER_EXTENSION", ROOT / "build/release/extension/gatekeeper/gatekeeper.duckdb_extension"))


def connect():
    db = duckdb.connect(config={"allow_unsigned_extensions": "true"})
    db.execute("LOAD '" + str(EXTENSION).replace("'", "''") + "'")
    return db


@pytest.fixture
def db():
    with connect() as connection:
        yield connection


@pytest.fixture
def populated(db):
        db.execute("""CREATE TABLE t(x VARCHAR, y INTEGER, z INTEGER, a INTEGER, b INTEGER);
            CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.t AS SELECT * FROM main.t;
            CREATE TABLE tenant_a.orders(id INTEGER, value DOUBLE);
            CREATE SCHEMA s; CREATE TABLE s.t AS SELECT * FROM main.t;
            CREATE TABLE s."*"(x INT);
            ATTACH ':memory:' AS db; CREATE SCHEMA db.s; CREATE TABLE db.s.t(x INT);
            CREATE MACRO custom(x) AS x;
            CREATE MACRO db.main.md5(x) AS system.main.md5(x)""")
        return db


@pytest.mark.parametrize("sql", [
    "SELECT 1", "VALUES (1),(2)", "SELECT 2*3", "SELECT sum(y) FROM main.t",
    "SELECT md5('x'), lower('Y')", "SELECT row_number() OVER ()",
    "SELECT list_transform([1,2], lambda x: x+1)",
    "SELECT DISTINCT ON (x) x FROM t ORDER BY x DESC NULLS LAST LIMIT 3 OFFSET 1",
    "SELECT CASE WHEN y BETWEEN 1 AND 3 THEN y::VARCHAR ELSE NULL END FROM t",
    "SELECT * REPLACE (upper(x) AS x) FROM t",
    "SELECT * EXCLUDE (x) FROM t",
    "SELECT 1 AS x UNION BY NAME SELECT 2 AS y", "SELECT 1 EXCEPT SELECT 2",
    "SELECT sum(y) FILTER (WHERE y>0) OVER (PARTITION BY x ORDER BY z ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t",
    "SELECT * FROM t TABLESAMPLE reservoir(10 ROWS)",
    "SELECT * FROM t PIVOT (sum(z) FOR y IN (1,2))",
    "SELECT * FROM t UNPIVOT (value FOR name IN (y,z))",
    "SELECT '{\"type\":\"DELETE_QUERY_NODE\"}'",
    "SELECT 'DROP TABLE t; --'", "SELECT * FROM range(3) WITH ORDINALITY",
])
def test_reads(populated, sql):
    result = check(populated, sql)
    assert result["allowed"], result
    assert result["code"] == "ok"
    assert result["violations"] == []


@pytest.mark.parametrize("sql", [
    "CREATE TABLE t(id INT)", "CREATE TABLE t AS SELECT 1", "DROP TABLE t",
    "ALTER TABLE t ADD COLUMN x INT", "CREATE VIEW v AS SELECT 1", "CREATE SCHEMA s",
    "CREATE MACRO f() AS 1", "INSERT INTO t VALUES (1)", "UPDATE t SET x=1",
    "DELETE FROM t RETURNING *", "TRUNCATE t", "COPY t TO 'file.csv'",
    "ATTACH ':memory:' AS other", "DETACH other", "SET threads=1", "PRAGMA version",
    "EXPLAIN ANALYZE DELETE FROM t", "CALL checkpoint()",
    "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN DELETE",
])
def test_writes(db, sql):
    result = check(db, sql)
    assert not result["allowed"]
    assert result["code"] == "unsupported"


def test_no_execution_or_binding(db, tmp_path):
    db.execute("CREATE TABLE existing AS SELECT 42 AS x")
    assert not check(db, "DROP TABLE existing")["allowed"]
    assert db.execute("SELECT * FROM existing").fetchone() == (42,)
    assert check(db, "SELECT * FROM nonexistent")["code"] == "binding"
    missing = str(tmp_path / "missing.parquet")
    configure(db, {"allowed_functions": ["read_parquet"]})
    assert check(db, f"SELECT * FROM read_parquet('{missing}')", {"allowed_functions": ["read_parquet"]})["code"] == "binding"


@pytest.mark.parametrize("sql,opts,allowed", [
    ("SELECT custom(1)", {}, False),
    ("SELECT custom(1)", {"allowed_functions": ["CUSTOM"]}, False),
    ("SELECT md5('x')", {"blocked_functions": ["MD5"]}, False),
    ("SELECT md5('x')", {"allowed_functions": ["md5"], "blocked_functions": ["md5"]}, False),
    ("SELECT sum(x) FROM t", {"use_default_functions": False}, False),
    ("SELECT sum(y) FROM t", {"use_default_functions": False, "allowed_functions": ["sum"]}, True),
    ("SELECT custom(1)", {"allowed_functions": ["custom"], "blocked_functions": ["custom"]}, False),
    ("SELECT * FROM read_parquet('local')", {}, False),
    ("SELECT 2*3", {"blocked_functions": ["*"]}, False),
    ("SELECT sum(y) FROM t", {"blocked_functions": ["*"]}, True),
    ("SELECT lower('x')", {"use_default_functions": False, "allowed_functions": ["*"]}, False),
    ("SELECT md5('x')", {"allowed_functions": ["md*"]}, True),
    ("SELECT custom(1)", {"allowed_functions": ["cust*"]}, False),
    ("SELECT * FROM range(3)", {}, True),
    ("SELECT range(3)", {}, True),
    ("SELECT * FROM range(3)", {"use_default_functions": False}, False),
    ("SELECT * FROM range(3)", {"use_default_functions": False, "allowed_functions": ["range"]}, True),
    ("SELECT * FROM range(3)", {"blocked_functions": ["range"]}, False),
    ("SELECT range(3)", {"blocked_functions": ["range"]}, False),
    ("SELECT * FROM query_table('t')", {"allowed_functions": ["query_table"]}, False),
    ("SELECT json_serialize_plan('SELECT 1')", {"allowed_functions": ["json_serialize_plan"]}, False),
    ("SELECT * FROM query('SELECT 1')", {"allowed_functions": ["query"]}, False),
    ("SELECT * FROM query('SELECT 1')", {}, False),
])
def test_functions(populated, sql, opts, allowed):
    result = check(populated, sql, opts)
    assert result["allowed"] == allowed, result


def test_occurrences(db):
    result = check(db, "SELECT md5('x'), md5('y')", {"blocked_functions": ["md5"]})
    assert len(result["violations"]) == 1
    assert "2 occurrences" in result["violations"][0]["message"]


@pytest.mark.parametrize("sql,opts,allowed", [
    ("SELECT * FROM db.s.t", {"allowed_tables": []}, False),
    ("SELECT * FROM db.s.t", {"allowed_tables": [{"catalog": "db", "schema": "*", "table": "*"}]}, True),
    ("SELECT * FROM other.s.t", {"allowed_tables": [{"catalog": "db", "schema": "*", "table": "*"}]}, False),
    ("SELECT db.main.md5('x')", {"allowed_tables": []}, True),
    ("SELECT * FROM s.t", {"allowed_tables": [{"catalog": "*", "schema": "s", "table": "*"}]}, True),
    ("SELECT * FROM t", {"allowed_tables": [{"catalog": "*", "schema": "s", "table": "*"}]}, False),
    ("SELECT * FROM s.t", {"allowed_tables": [{"schema": "s", "table": "t"}]}, True),
    ("SELECT * FROM db.s.t", {"allowed_tables": [{"schema": "s", "table": "t"}]}, True),
    ("SELECT * FROM db.s.t", {"allowed_tables": [{"catalog": "db", "schema": "s", "table": "t"}]}, True),
    ("SELECT * FROM s.t", {"allowed_tables": []}, False),
    ("SELECT 1", {"allowed_tables": []}, True),
    ("SELECT * FROM s.t", {"allowed_tables": [{"schema": "s", "table": "*"}]}, True),
    ('SELECT * FROM s."*"', {"allowed_tables": [{"schema": "s", "table": "*"}]}, True),
    ("SHOW TABLES FROM s", {"allowed_tables": [{"catalog": "*", "schema": "s", "table": "*"}]}, False),
    ("SHOW ALL TABLES", {"allowed_tables": [{"catalog": "*", "schema": "s", "table": "*"}]}, False),
    ("SHOW TABLES FROM s", {"allowed_tables": [{"schema": "s", "table": "t"}]}, False),
    ("DESCRIBE s.t", {"allowed_tables": [{"schema": "s", "table": "t"}]}, True),
])
def test_objects(populated, sql, opts, allowed):
    result = check(populated, sql, opts)
    assert result["allowed"] == allowed, result


@pytest.mark.parametrize("sql,allowed", [
    ("WITH t AS (SELECT 1) SELECT * FROM t", True),
    ("WITH t AS (SELECT * FROM t) SELECT * FROM t", False),
    ("WITH a AS (SELECT * FROM b), b AS (SELECT 1) SELECT * FROM a", False),
    ("WITH z AS (SELECT 1), a AS (SELECT * FROM z) SELECT * FROM a", True),
    ("SELECT * FROM secret WHERE EXISTS (WITH secret AS (SELECT 1) SELECT * FROM secret)", False),
    ("WITH t AS (SELECT 1) SELECT * FROM (WITH t AS (SELECT * FROM t) SELECT * FROM t)", True),
    ("WITH T AS (SELECT 1) SELECT * FROM t", True),
    ("WITH RECURSIVE t AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM t WHERE n<3) SELECT * FROM t", True),
    ("WITH RECURSIVE t AS (SELECT * FROM t UNION ALL SELECT 1 WHERE false) SELECT * FROM t", False),
    ('WITH "mine.parquet" AS (SELECT 1) SELECT * FROM "mine.parquet"', True),
])
def test_ctes(db, sql, allowed):
    result = check(db, sql, {"allowed_tables": []})
    assert result["allowed"] == allowed, result


def test_recursive_cte_obeys_function_and_table_policy(db):
    sql = "WITH RECURSIVE t AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM t WHERE n<3) SELECT * FROM t"
    assert check(db, sql, {"allowed_tables": []})["allowed"]
    assert not check(db, sql, {"blocked_functions": ["+"]})["allowed"]
    db.execute("CREATE TABLE secret(n INT)")
    assert not check(db, sql.replace("SELECT 1 AS n", "SELECT n FROM secret"), {"allowed_tables": []})["allowed"]


@pytest.mark.parametrize("sql,opts,allowed", [
    ("SELECT * FROM 'mine.parquet'", {}, False),
    ("SELECT * FROM parquet_scan('mine.parquet')", {}, False),
    ("SELECT * FROM 's3://bucket/data'", {}, False),
    ("SELECT * FROM read_parquet('local.parquet')", {}, False),
    ("SELECT * FROM read_parquet('s3://bucket/file')", {}, False),
    ("SELECT 'https://example.com'", {}, True),
])
def test_paths(db, sql, opts, allowed):
    result = check(db, sql, opts)
    assert result["allowed"] == allowed, result


@pytest.mark.parametrize("sql", ["SELECT 1", "SELECT 1;", "SELECT 1; -- trailing comment",
                                  "SELECT 1;;", "SELECT 1; ;", ";SELECT 1",
                                  "SELECT ';'", "SELECT 1 /* ; SELECT 2 */"])
def test_single_statement_boundary(db, sql):
    assert check(db, sql)["allowed"]


@pytest.mark.parametrize("sql", ["SELECT 1; SELECT 2", "SELECT 1; -- comment\n SELECT 2",
                                  "WITH t AS (SELECT 1) SELECT * FROM t; SELECT * FROM t",
                                  "SELECT * FROM missing; SELECT 2"])
def test_fixed_statement_limit_precedes_binding(db, sql):
    configure(db, {"use_default_functions": False})
    result = check(db, sql, {"use_default_functions": True})
    assert not result["allowed"] and result["code"] == "forbidden"
    assert result["violations"][0]["rule"] == "limit"
    assert result["objects"] == result["functions"] == []
    assert result["error_message"] == ""


@pytest.mark.parametrize("options", [
    "null", "[]", "false", "{", '{"unknown":true}', '{"check_functions":"false"}',
    '{"check_functions":false,"check_functions":true}', '{"allowed_functions":null}',
    '{"allowed_tables":[{"table":"t"}]}', '{"allowed_tables":[{"schema":"s","table":"t","unknown":"x"}]}',
    '{"limits":{"max_statements":0}}', '{"limits":{"max_ast_depth":513}}',
    '{"limits":{"unknown":1}}', '{"reader_paths":"literal_local"}',
    '{"check_functions":false,"use_default_functions":true}',
])
def test_invalid_options(db, options):
    with pytest.raises(duckdb.BinderException, match="No function matches"):
        db.execute("SELECT * FROM gatekeeper_validate('SELECT 1', ?)", [options])


def test_parser_and_null_inputs(db):
    result = check(db, "SELECT * FROM")
    assert result["code"] == "parser" and result["error_message"]
    assert db.execute("SELECT code FROM gatekeeper_validate(NULL)").fetchall() == [("invalid_input",)]
    assert db.execute("SELECT code FROM gatekeeper_validate('SELECT 1',blocked_functions := NULL)").fetchall() == [("invalid_input",)]


def test_concurrent_policies():
    with connect() as db:
        for i in range(8):
            db.execute(f"CREATE SCHEMA tenant_{i}; CREATE TABLE tenant_{i}.t(x INT)")
        def worker(i):
            with db.cursor() as conn:
                for j in range(30):
                    policy = {"allowed_tables": [{"catalog": "*", "schema": f"tenant_{i}" if j%2 == 0 else "other", "table": "*"}]}
                    result = check(conn, f"SELECT sum(x) FROM tenant_{i}.t", policy)
                    assert result["allowed"] == (j%2 == 0), result
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(8)))
