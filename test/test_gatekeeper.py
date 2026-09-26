"""Decisions of gatekeeper_validate: statement kinds, functions, objects, CTEs, paths, limits, concurrency."""
import concurrent.futures

import duckdb
import pytest

from support.artifact import by_parser, connect
from support.typed_helpers import configure, function_rules, validate


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
    result = validate(populated, sql)
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
    result = validate(db, sql)
    assert not result["allowed"]
    assert result["code"] == "unsupported"


def test_validation_binds_without_executing(db, tmp_path):
    db.execute("CREATE TABLE existing AS SELECT 42 AS x")
    assert not validate(db, "DROP TABLE existing")["allowed"]
    assert db.execute("SELECT * FROM existing").fetchone() == (42,)
    assert validate(db, "SELECT * FROM nonexistent")["code"] == "binding"
    missing = str(tmp_path / "missing.parquet")
    configure(db, {"allowed_functions": [{"schema_path": ["*"], "name": "read_parquet"}]})
    assert validate(db, f"SELECT * FROM read_parquet('{missing}')", {"allowed_functions": [{"schema_path": ["*"], "name": "read_parquet"}]})["code"] == "binding"


@pytest.mark.parametrize("sql,opts,allowed", [
    ("SELECT custom(1)", {}, False),
    ("SELECT custom(1)", {"allowed_functions": [{"schema_path": ["*"], "name": "CUSTOM"}]}, False),
    ("SELECT md5('x')", {"blocked_functions": function_rules("MD5")}, False),
    ("SELECT md5('x')", {"allowed_functions": [{"schema_path": ["*"], "name": "md5"}], "blocked_functions": function_rules("md5")}, False),
    ("SELECT sum(x) FROM t", {"use_default_functions": False}, False),
    ("SELECT sum(y) FROM t", {"use_default_functions": False, "allowed_functions": [{"schema_path": ["*"], "name": "sum"}]}, True),
    ("SELECT custom(1)", {"allowed_functions": [{"schema_path": ["*"], "name": "custom"}], "blocked_functions": function_rules("custom")}, False),
    ("SELECT * FROM read_parquet('local')", {}, False),
    ("SELECT 2*3", {"blocked_functions": function_rules("*")}, False),
    ("SELECT sum(y) FROM t", {"blocked_functions": function_rules("*")}, True),
    ("SELECT lower('x')", {"use_default_functions": False, "allowed_functions": [{"schema_path": ["*"], "name": "*"}]}, False),
    ("SELECT md5('x')", {"allowed_functions": [{"schema_path": ["*"], "name": "md*"}]}, True),
    ("SELECT custom(1)", {"allowed_functions": [{"schema_path": ["*"], "name": "cust*"}]}, False),
    ("SELECT * FROM range(3)", {}, True),
    ("SELECT range(3)", {}, True),
    ("SELECT * FROM range(3)", {"use_default_functions": False}, False),
    ("SELECT * FROM range(3)", {"use_default_functions": False, "allowed_functions": [{"schema_path": ["*"], "name": "range"}]}, True),
    ("SELECT * FROM range(3)", {"blocked_functions": function_rules("range")}, False),
    ("SELECT range(3)", {"blocked_functions": function_rules("range")}, False),
    ("SELECT * FROM query_table('t')", {"allowed_functions": [{"schema_path": ["*"], "name": "query_table"}]}, False),
    ("SELECT json_serialize_plan('SELECT 1')", {"allowed_functions": [{"schema_path": ["*"], "name": "json_serialize_plan"}]}, False),
    ("SELECT * FROM query('SELECT 1')", {"allowed_functions": [{"schema_path": ["*"], "name": "query"}]}, False),
    ("SELECT * FROM query('SELECT 1')", {}, False),
])
def test_functions(populated, sql, opts, allowed):
    result = validate(populated, sql, opts)
    assert result["allowed"] == allowed, result


def test_occurrences(db):
    result = validate(db, "SELECT md5('x'), md5('y')", {"blocked_functions": function_rules("md5")})
    assert len(result["violations"]) == 1
    assert "2 occurrences" in result["violations"][0]["message"]


@pytest.mark.parametrize("sql,position", [
    # A written name repeated: the first occurrence in the text, whatever order the walk visits them in.
    ("SELECT md5('x'), md5('y')", 7),
    ("SELECT x FROM (SELECT md5('a') x) WHERE md5('b') = x", 22),
    ("SELECT list_value(1), list_value(2)", 7),
    # A name written and implied by syntax (ARRAY[..] is list_value), in either order. The default parser
    # stamps no location on the operator node, so the written occurrence's position is the earliest one on
    # record; the PEG parser stamps the ARRAY keyword's, which then is the earliest.
    ("SELECT list_value(1), ARRAY[2]", 7),
    ("SELECT ARRAY[1], list_value(2)", by_parser(postgres=17, peg=7)),
    # Only implied: under the default parser no occurrence has a location, and the violation says so rather
    # than inventing one.
    ("SELECT ARRAY[1], ARRAY[2]", by_parser(postgres=None, peg=7)),
])
def test_function_position_is_the_earliest_occurrence(db, sql, position):
    name = "md5" if "md5" in sql else "list_value"
    [violation] = validate(db, sql, {"blocked_functions": function_rules(name)})["violations"]
    assert violation["function_name"] == name and "2 occurrences" in violation["message"], violation
    assert violation["position"] == position


@pytest.mark.parametrize("sql,opts,allowed", [
    ("SELECT * FROM db.s.t", {"allowed_tables": []}, False),
    ("SELECT * FROM db.s.t", {"allowed_tables": [{"catalog": "db", "schema_path": ["*"], "table": "*"}]}, True),
    ("SELECT * FROM other.s.t", {"allowed_tables": [{"catalog": "db", "schema_path": ["*"], "table": "*"}]}, False),
    ("SELECT db.main.md5('x')", {"allowed_tables": []}, False),
    ("SELECT * FROM s.t", {"allowed_tables": [{"catalog": "*", "schema_path": ["s"], "table": "*"}]}, True),
    ("SELECT * FROM t", {"allowed_tables": [{"catalog": "*", "schema_path": ["s"], "table": "*"}]}, False),
    ("SELECT * FROM s.t", {"allowed_tables": [{"schema_path": ["s"], "table": "t"}]}, True),
    ("SELECT * FROM db.s.t", {"allowed_tables": [{"schema_path": ["s"], "table": "t"}]}, True),
    ("SELECT * FROM db.s.t", {"allowed_tables": [{"catalog": "db", "schema_path": ["s"], "table": "t"}]}, True),
    ("SELECT * FROM s.t", {"allowed_tables": []}, False),
    ("SELECT 1", {"allowed_tables": []}, True),
    ("SELECT * FROM s.t", {"allowed_tables": [{"schema_path": ["s"], "table": "*"}]}, True),
    ('SELECT * FROM s."*"', {"allowed_tables": [{"schema_path": ["s"], "table": "*"}]}, True),
    ("SHOW TABLES FROM s", {"allowed_tables": [{"catalog": "*", "schema_path": ["s"], "table": "*"}]}, False),
    ("SHOW ALL TABLES", {"allowed_tables": [{"catalog": "*", "schema_path": ["s"], "table": "*"}]}, False),
    ("SHOW TABLES FROM s", {"allowed_tables": [{"schema_path": ["s"], "table": "t"}]}, False),
    ("DESCRIBE s.t", {"allowed_tables": [{"schema_path": ["s"], "table": "t"}]}, True),
])
def test_objects(populated, sql, opts, allowed):
    result = validate(populated, sql, opts)
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
    result = validate(db, sql, {"allowed_tables": []})
    assert result["allowed"] == allowed, result


def test_recursive_cte_obeys_function_and_table_policy(db):
    sql = "WITH RECURSIVE t AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM t WHERE n<3) SELECT * FROM t"
    assert validate(db, sql, {"allowed_tables": []})["allowed"]
    assert not validate(db, sql, {"blocked_functions": function_rules("+")})["allowed"]
    db.execute("CREATE TABLE secret(n INT)")
    assert not validate(db, sql.replace("SELECT 1 AS n", "SELECT n FROM secret"), {"allowed_tables": []})["allowed"]


@pytest.mark.parametrize("sql,opts,allowed", [
    ("SELECT * FROM 'mine.parquet'", {}, False),
    ("SELECT * FROM parquet_scan('mine.parquet')", {}, False),
    ("SELECT * FROM 's3://bucket/data'", {}, False),
    ("SELECT * FROM read_parquet('local.parquet')", {}, False),
    ("SELECT * FROM read_parquet('s3://bucket/file')", {}, False),
    ("SELECT 'https://example.com'", {}, True),
])
def test_paths(db, sql, opts, allowed):
    result = validate(db, sql, opts)
    assert result["allowed"] == allowed, result


@pytest.mark.parametrize("sql", ["SELECT 1", "SELECT 1;", "SELECT 1; -- trailing comment",
                                  "SELECT 1;;", "SELECT 1; ;", ";SELECT 1",
                                  "SELECT ';'", "SELECT 1 /* ; SELECT 2 */"])
def test_single_statement_boundary(db, sql):
    assert validate(db, sql)["allowed"]


@pytest.mark.parametrize("sql", ["SELECT 1; SELECT 2", "SELECT 1; -- comment\n SELECT 2",
                                  "WITH t AS (SELECT 1) SELECT * FROM t; SELECT * FROM t",
                                  "SELECT * FROM missing; SELECT 2"])
def test_fixed_statement_limit_precedes_binding(db, sql):
    configure(db, {"use_default_functions": False})
    result = validate(db, sql, {"use_default_functions": True})
    assert not result["allowed"] and result["code"] == "forbidden"
    assert result["violations"][0]["rule"] == "limit"
    assert result["objects"] == result["functions"] == []
    assert result["error_message"] == ""


def test_options_must_be_named(db):
    with pytest.raises(duckdb.BinderException, match="No function matches"):
        db.execute("SELECT * FROM gatekeeper_validate('SELECT 1', ?)", ["{}"])


def test_parser_and_null_inputs(db):
    result = validate(db, "SELECT * FROM")
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
                    policy = {"allowed_tables": [{"catalog": "*", "schema_path": [f"tenant_{i}" if j%2 == 0 else "other"], "table": "*"}]}
                    result = validate(conn, f"SELECT sum(x) FROM tenant_{i}.t", policy)
                    assert result["allowed"] == (j%2 == 0), result
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(8)))


def test_configure_interleaved_with_validate():
    """Each validation reads one coherent policy snapshot while another connection replaces the global policy.
    The two policies differ in both dimensions; a torn read would pass one dimension and fail the other."""
    with connect() as db:
        db.execute("CREATE TABLE a(x INT); CREATE TABLE b(x INT)")
        policies = [
            {"allowed_tables": [{"schema_path": ["main"], "table": "a"}], "blocked_functions": function_rules("sum")},
            {"allowed_tables": [{"schema_path": ["main"], "table": "b"}], "blocked_functions": function_rules("count")},
        ]
        stop = False
        configure(db, policies[0])  # never validate against the built-in defaults

        def configurer():
            with db.cursor() as conn:
                i = 0
                while not stop:
                    configure(conn, policies[i % 2])
                    i += 1

        def validator(_):
            with db.cursor() as conn:
                for _ in range(200):
                    # Policy 0: a allowed, b denied, sum blocked. Policy 1 is the mirror image. Queries denied
                    # under both policies must never come back ok, whichever snapshot a call happened to take;
                    # a torn read (tables from one policy, functions from the other) would let one through.
                    assert validate(conn, "SELECT sum(x) FROM a")["code"] == "forbidden"
                    assert validate(conn, "SELECT count(x) FROM b")["code"] == "forbidden"
                    assert validate(conn, "SELECT sum(x) FROM a, b")["code"] == "forbidden"
                    assert validate(conn, "SELECT count(x) FROM a")["code"] in ("ok", "forbidden")
                    assert validate(conn, "SELECT sum(x) FROM b")["code"] in ("ok", "forbidden")

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            background = pool.submit(configurer)
            try:
                list(pool.map(validator, range(4)))
            finally:
                stop = True
                background.result(timeout=30)
