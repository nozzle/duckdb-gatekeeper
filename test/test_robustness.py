import json
import random

import duckdb
import pytest

from support.artifact import PARSER
from support.typed_helpers import validate

# DuckDB 1.5.5's PEG matcher recurses once per nesting level with no depth guard and no stack check, and
# gatekeeper_validate with a parameter parses at execution on whichever thread runs the pipeline: a worker
# thread's 512 KiB stack (macOS) overflows at about 75 nested calls or 100 nested subqueries, and the engine's
# own parse overflows the 8 MiB main-thread stack at about 1000, under max_expression_depth's default. The
# process dies (SIGBUS/SIGILL); nothing downstream, Gatekeeper's depth limit included, ever runs. This is the
# engine's to bound (docs/security.md, "Compatibility and review"); these two cases are the ones deep enough
# to reach it and are run only under the default parser until it does.
PEG_DEEP_NESTING_CRASH = pytest.mark.skipif(
    PARSER == "peg", reason="DuckDB 1.5.5 PEG parser recursion overflows the stack on deep nesting")


@pytest.mark.parametrize("depth", [1, 20, pytest.param(100, marks=PEG_DEEP_NESTING_CRASH)])
def test_depth(db, depth):
    db.execute("CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.t(x INT)")
    sql = "SELECT * FROM " + "(SELECT * FROM " * depth + "tenant_a.t" + ") t" * depth
    assert validate(db, sql, {"allowed_tables": [{"catalog": "*", "schema": "tenant_a", "table": "*"}]})["allowed"]
    assert not validate(db, sql, {"allowed_tables": [{"catalog": "*", "schema": "tenant_b", "table": "*"}]})["allowed"]


def test_width(db):
    sql = "SELECT " + ",".join(str(i) for i in range(1000))
    assert validate(db, sql)["allowed"]


@pytest.mark.parametrize("sql,message", [
    ("SELECT '" + "x" * 8388608 + "'", "SQL exceeds fixed input size limit"),
    # The input fits, but AST serialization adds enough overhead to exceed 8 MiB.
    ("SELECT '" + "x" * (8388608 - 9) + "'", "serialized AST exceeds fixed size limit"),
    # Traversal counts fields/arrays too; leave margin above node/depth thresholds
    # while staying below the serialized-byte and connection parser limits.
    ("SELECT " + ",".join("1" for _ in range(40000)), "AST size or depth limit exceeded"),
    pytest.param("SELECT " + "abs(" * 400 + "1" + ")" * 400, "AST size or depth limit exceeded",
                 marks=PEG_DEEP_NESTING_CRASH),
], ids=["input-bytes", "serialized-bytes", "nodes", "depth"])
def test_fixed_ast_guardrails_and_recovery(db, sql, message):
    if message == "serialized AST exceeds fixed size limit":
        assert len(sql.encode()) == 8388608
    result = validate(db, sql)
    assert result["code"] == "forbidden" and not result["allowed"], result
    assert result["violations"][0]["rule"] == "limit"
    assert result["violations"][0]["message"] == message
    assert result["objects"] == result["functions"] == []
    assert validate(db, "SELECT 1")["allowed"]


def test_nul(db):
    assert validate(db, "SELECT 1\0; DROP TABLE t")["code"] == "invalid_input"


def test_random_invalid_sql(db):
    rng = random.Random(42)
    alphabet = "abcXYZ012 ()[]'\";+-/\\\n\t"
    for _ in range(500):
        sql = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 200)))
        result = validate(db, sql)
        assert set(result) == {"allowed", "code", "violations", "error_type", "error_message", "position", "objects", "functions", "caller_objects"}
        assert result["code"] in {"ok", "forbidden", "unsupported", "parser", "invalid_input", "binding"}
        assert result["allowed"] == (result["code"] == "ok")


def test_random_option_types(db):
    rng = random.Random(99)
    values = [None, True, False, 1, -1, 1.5, "x", [], {}, ["x"]]
    keys = ["use_default_functions", "allowed_functions", "blocked_functions", "allowed_tables", "blocked_tables", "unknown"]
    for _ in range(100):
        options = {rng.choice(keys): rng.choice(values)}
        try:
            result = validate(db, "SELECT 1", options)
        except duckdb.Error:
            continue
        assert result["allowed"] == (result["code"] == "ok"), json.dumps(options)


def test_filtered_table_result(db):
    for blocks, allowed_count in [([], 6666), (["md5"], 0)]:
        result = db.execute("""SELECT count(*) FILTER (WHERE r.allowed), count(*)
            FROM range(10000) t(i) CROSS JOIN gatekeeper_validate('SELECT md5(''x'')',
                blocked_functions := ?) r WHERE i%3!=0""", [blocks]).fetchone()
        assert result == (allowed_count, 6666)


def test_literal_path_and_quoted_cte_names(db):
    for name in ["a.b", "a'b", "x[0]", "a\\b", "s3://bucket/file"]:
        ident = '"' + name.replace('"', '""') + '"'
        assert validate(db, f"WITH {ident} AS (SELECT 1) SELECT * FROM {ident}", {"allowed_tables": []})["allowed"]
    assert not validate(db, "SELECT * FROM read_parquet(main.list_value('s3://bucket/file'))", {
        "blocked_functions": ["read_parquet"]
    })["allowed"]
