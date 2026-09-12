import concurrent.futures
import json
import os
from pathlib import Path

import duckdb
import pytest

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


def check(db, sql, options=None):
    options = {"resolve_objects": False, **(options or {})}
    return db.execute("SELECT gatekeeper_validate(?, ?)", [sql, json.dumps(options)]).fetchone()[0]


@pytest.mark.parametrize("sql", [
    "SELECT 1", "VALUES (1),(2)", "SELECT 2*3", "SELECT sum(x) FROM main.t",
    "SELECT md5('x'), lower('Y')", "SELECT row_number() OVER ()",
    "SELECT list_transform([1,2], lambda x: x+1)",
    "SELECT DISTINCT ON (x) x FROM t ORDER BY x DESC NULLS LAST LIMIT 3 OFFSET 1",
    "SELECT CASE WHEN x BETWEEN 1 AND 3 THEN x::VARCHAR ELSE NULL END FROM t",
    "SELECT * REPLACE (upper(x) AS x) FROM t",
    "SELECT * EXCLUDE (x) FROM t", "SELECT CURRENT_DATE",
    "SELECT 1 AS x UNION BY NAME SELECT 2 AS y", "SELECT 1 EXCEPT SELECT 2",
    "SELECT sum(x) FILTER (WHERE x>0) OVER (PARTITION BY y ORDER BY z ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t",
    "SELECT * FROM t TABLESAMPLE reservoir(10 ROWS)",
    "SELECT * FROM t PIVOT (sum(x) FOR y IN (1,2))",
    "SELECT * FROM t UNPIVOT (value FOR name IN (x,y))",
    "SELECT '{\"type\":\"DELETE_QUERY_NODE\"}'::JSON",
    "SELECT 'DROP TABLE t; --'", "SELECT * FROM range(3) WITH ORDINALITY",
])
def test_reads(db, sql):
    result = check(db, sql)
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
    assert check(db, "SELECT * FROM nonexistent")["allowed"]
    missing = str(tmp_path / "missing.parquet")
    assert check(db, f"SELECT * FROM read_parquet('{missing}')", {"allowed_functions": ["read_parquet"]})["allowed"]


@pytest.mark.parametrize("sql,opts,allowed", [
    ("SELECT custom(1)", {}, False),
    ("SELECT custom(1)", {"allowed_functions": ["CUSTOM"]}, True),
    ("SELECT md5('x')", {"blocked_functions": ["MD5"]}, False),
    ("SELECT md5('x')", {"allowed_functions": ["md5"], "blocked_functions": ["md5"]}, False),
    ("SELECT sum(x) FROM t", {"use_default_functions": False}, False),
    ("SELECT sum(x) FROM t", {"use_default_functions": False, "allowed_functions": ["sum"]}, True),
    ("SELECT custom(1)", {"check_functions": False}, True),
    ("SELECT custom(1)", {"check_functions": False, "blocked_functions": ["custom"]}, False),
    ("SELECT * FROM read_parquet('local')", {}, False),
    ("SELECT 2*3", {"blocked_functions": ["*"]}, False),
    ("SELECT sum(x) FROM t", {"blocked_functions": ["*"]}, True),
    ("SELECT lower('x')", {"use_default_functions": False, "allowed_functions": ["*"]}, False),
    ("SELECT md5('x')", {"allowed_functions": ["md*"]}, True),
    ("SELECT custom(1)", {"allowed_functions": ["cust*"]}, False),
    ("SELECT * FROM range(3)", {"allow_table_functions": False}, False),
    ("SELECT range(3)", {"allow_table_functions": False}, True),
    ("SELECT * FROM query('SELECT 1')", {"check_functions": False}, False),
    ("SELECT * FROM query_table('t')", {"check_functions": False}, False),
    ("SELECT json_serialize_plan('SELECT 1')", {"allowed_functions": ["json_serialize_plan"]}, False),
    ("SELECT * FROM query('SELECT 1')", {"allowed_functions": ["query"], "allow_dynamic_sql": True}, True),
    ("SELECT * FROM query('SELECT 1')", {"allow_dynamic_sql": True}, False),
])
def test_functions(db, sql, opts, allowed):
    result = check(db, sql, opts)
    assert result["allowed"] == allowed, result


def test_occurrences(db):
    result = check(db, "SELECT md5('x'), md5('y')", {"blocked_functions": ["md5"]})
    assert len(result["violations"]) == 1
    assert "2 occurrences" in result["violations"][0]


@pytest.mark.parametrize("sql,opts,allowed", [
    ("SELECT * FROM db.s.t", {"allowed_catalogs": []}, False),
    ("SELECT * FROM db.s.t", {"allowed_catalogs": ["db"]}, True),
    ("SELECT * FROM other.s.t", {"allowed_catalogs": ["db"]}, False),
    ("SELECT * FROM s.t", {"allowed_catalogs": []}, True),
    ("SELECT db.main.md5('x')", {"allowed_catalogs": []}, False),
    ("SELECT db.main.md5('x')", {"allowed_catalogs": ["db"]}, True),
    ("SELECT * FROM s.t", {"allowed_schemas": ["s"]}, True),
    ("SELECT * FROM t", {"allowed_schemas": ["s"]}, False),
    ("SELECT * FROM s.t", {"allowed_schemas": []}, False),
    ("SELECT 1", {"allowed_schemas": []}, True),
    ("SELECT * FROM s.t", {"allowed_tables": [{"schema": "s", "table": "t"}]}, True),
    ("SELECT * FROM db.s.t", {"allowed_tables": [{"schema": "s", "table": "t"}]}, False),
    ("SELECT * FROM db.s.t", {"allowed_tables": [{"catalog": "db", "schema": "s", "table": "t"}]}, True),
    ("SELECT * FROM s.t", {"allowed_tables": []}, False),
    ("SELECT 1", {"allowed_tables": []}, True),
    ("SELECT * FROM s.t", {"allowed_tables": [{"schema": "s", "table": "*"}]}, False),
    ('SELECT * FROM s."*"', {"allowed_tables": [{"schema": "s", "table": "*"}]}, True),
    ("SELECT * FROM s.t", {"allowed_tables": [{"schema": "s", "table": "t"}], "allowed_schemas": ["other"]}, False),
    ("SHOW TABLES FROM s", {"allowed_schemas": ["s"]}, True),
    ("SHOW ALL TABLES", {"allowed_schemas": ["s"]}, False),
    ("SHOW TABLES FROM s", {"allowed_tables": [{"schema": "s", "table": "t"}]}, False),
    ("DESCRIBE s.t", {"allowed_tables": [{"schema": "s", "table": "t"}]}, True),
])
def test_objects(db, sql, opts, allowed):
    result = check(db, sql, opts)
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
    result = check(db, sql, {"allowed_schemas": [], "allowed_tables": []})
    assert result["allowed"] == allowed, result


def test_recursive_toggle(db):
    sql = "WITH RECURSIVE t AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM t WHERE n<3) SELECT * FROM t"
    assert not check(db, sql, {"allow_recursive_ctes": False})["allowed"]


@pytest.mark.parametrize("sql,opts,allowed", [
    ("SELECT * FROM 'mine.parquet'", {}, False),
    ("SELECT * FROM 'mine.parquet'", {"allow_file_table_references": True}, True),
    ("SELECT * FROM 's3://bucket/data'", {}, False),
    ("SELECT * FROM 's3://bucket/data'", {"allow_file_table_references": True}, True),
    ("SELECT * FROM read_parquet('local.parquet')", {}, False),
    ("SELECT * FROM read_parquet('s3://bucket/file')", {}, False),
    ("SELECT * FROM read_parquet('s3://bucket/file')", {"allowed_functions": ["read_parquet"]}, True),
    ("SELECT * FROM read_parquet('x' || '.parquet')", {"allowed_functions": ["read_parquet"]}, True),
    ("SELECT 'https://example.com'", {}, True),
])
def test_paths(db, sql, opts, allowed):
    result = check(db, sql, opts)
    assert result["allowed"] == allowed, result


def test_limits(db):
    assert not check(db, "")["allowed"]
    assert not check(db, "SELECT 1; SELECT 2")["allowed"]
    assert check(db, "SELECT 1; SELECT 2", {"limits": {"max_statements": 2}})["allowed"]
    assert not check(db, "WITH t AS (SELECT 1) SELECT * FROM t; SELECT * FROM t", {"limits": {"max_statements": 2}, "allowed_tables": []})["allowed"]
    for limits in [{"max_ast_nodes": 1}, {"max_ast_depth": 1}, {"max_ast_bytes": 50}]:
        assert not check(db, "SELECT 1", {"limits": limits})["allowed"]


@pytest.mark.parametrize("options", [
    "null", "[]", "false", "{", '{"unknown":true}', '{"check_functions":"false"}',
    '{"check_functions":false,"check_functions":true}', '{"allowed_functions":null}',
    '{"allowed_tables":[{"table":"t"}]}', '{"allowed_tables":[{"schema":"s","table":"t","unknown":"x"}]}',
    '{"limits":{"max_statements":0}}', '{"limits":{"max_ast_depth":513}}',
    '{"limits":{"unknown":1}}', '{"reader_paths":"literal_local"}',
    '{"check_functions":false,"use_default_functions":true}',
])
def test_invalid_options(db, options):
    result = db.execute("SELECT gatekeeper_validate('SELECT 1', ?)", [options]).fetchone()[0]
    assert not result["allowed"]
    assert result["code"] == "invalid_input"


def test_parser_null_batch(db):
    result = check(db, "SELECT * FROM")
    assert result["code"] == "parser" and result["error_message"]
    assert db.execute("SELECT gatekeeper_validate(NULL)").fetchone()[0]["code"] == "invalid_input"
    assert db.execute("SELECT gatekeeper_validate('SELECT 1',NULL)").fetchone()[0]["code"] == "invalid_input"
    count = db.execute("""SELECT count(*) FROM (
        SELECT gatekeeper_validate(CASE WHEN i%2=0 THEN 'SELECT 1' ELSE 'DROP TABLE t' END) AS r
        FROM range(5000) t(i)) WHERE NOT r.allowed""").fetchone()[0]
    assert count == 2500


def test_concurrent_policies():
    with connect() as db:
        def worker(i):
            with db.cursor() as conn:
                for j in range(30):
                    policy = {"allowed_schemas": [f"tenant_{i}" if j%2 == 0 else "other"]}
                    result = check(conn, f"SELECT sum(x) FROM tenant_{i}.t", policy)
                    assert result["allowed"] == (j%2 == 0), result
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(8)))
