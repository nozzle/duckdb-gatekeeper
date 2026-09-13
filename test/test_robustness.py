import json
import random

from test_gatekeeper import check, db
import duckdb


def test_depth_and_width(db):
    db.execute("CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.t(x INT)")
    for depth in [1, 20, 100]:
        sql = "SELECT * FROM " + "(SELECT * FROM " * depth + "tenant_a.t" + ") t" * depth
        assert check(db, sql, {"allowed_tables": [{"catalog": "*", "schema": "tenant_a", "table": "*"}]})["allowed"]
        assert not check(db, sql, {"allowed_tables": [{"catalog": "*", "schema": "tenant_b", "table": "*"}]})["allowed"]
    sql = "SELECT " + ",".join(str(i) for i in range(1000))
    assert check(db, sql)["allowed"]
    assert not check(db, sql, {"max_ast_nodes": 10})["allowed"]


def test_nul(db):
    assert check(db, "SELECT 1\0; DROP TABLE t")["code"] == "invalid_input"


def test_random_invalid_sql(db):
    rng = random.Random(42)
    alphabet = "abcXYZ012 ()[]'\";+-/\\\n\t"
    for _ in range(500):
        sql = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 200)))
        result = check(db, sql)
        assert set(result) == {"allowed", "code", "violations", "error_type", "error_message", "position", "objects", "functions"}
        assert result["code"] in {"ok", "forbidden", "unsupported", "parser", "invalid_input", "binding"}
        assert result["allowed"] == (result["code"] == "ok")


def test_random_option_types(db):
    rng = random.Random(99)
    values = [None, True, False, 1, -1, 1.5, "x", [], {}, ["x"]]
    keys = ["check_functions", "allowed_functions", "allowed_tables", "limits", "reader_paths", "allow_dynamic_sql"]  # last three are unknown names
    for _ in range(100):
        options = {rng.choice(keys): rng.choice(values)}
        try:
            result = check(db, "SELECT 1", options)
        except duckdb.Error:
            continue
        assert result["allowed"] == (result["code"] == "ok"), json.dumps(options)


def test_filtered_vector_and_varying_options(db):
    result = db.execute("""SELECT count(*) FILTER (WHERE r.allowed), count(*) FROM (
        SELECT gatekeeper_validate('SELECT md5(''x'')',
            blocked_functions := CASE WHEN i%2=0 THEN []::VARCHAR[] ELSE ['md5'] END) AS r
        FROM range(10000) t(i) WHERE i%3!=0)""").fetchone()
    assert result == (3333, 6666)


def test_literal_path_and_quoted_cte_names(db):
    for name in ["a.b", "a'b", "x[0]", "a\\b", "s3://bucket/file"]:
        ident = '"' + name.replace('"', '""') + '"'
        assert check(db, f"WITH {ident} AS (SELECT 1) SELECT * FROM {ident}", {"allowed_tables": []})["allowed"]
    assert not check(db, "SELECT * FROM read_parquet(main.list_value('s3://bucket/file'))", {
        "blocked_functions": ["read_parquet"]
    })["allowed"]
