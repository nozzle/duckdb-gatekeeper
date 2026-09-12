"""Deterministic generated combinations with independently specified outcomes."""
import json
import random

from test_binding import validate
from test_gatekeeper import db


def test_generated_nested_reference_positions(db):
    db.execute("CREATE SCHEMA visible; CREATE SCHEMA hidden; CREATE TABLE visible.t AS SELECT 1 x; CREATE TABLE hidden.t AS SELECT 2 x")
    rng = random.Random(913)
    wrappers = [
        lambda q: f"SELECT * FROM ({q}) nested",
        lambda q: f"WITH local_cte AS ({q}) SELECT * FROM local_cte",
        lambda q: f"SELECT * FROM visible.t WHERE x IN ({q})",
        lambda q: f"SELECT ({q}) AS x",
        lambda q: f"SELECT * FROM visible.t UNION ALL ({q})",
    ]
    for _ in range(100):
        allowed = "SELECT x FROM visible.t"
        denied = "SELECT x FROM hidden.t"
        for _ in range(rng.randrange(1, 7)):
            wrap = rng.choice(wrappers)
            allowed, denied = wrap(allowed), wrap(denied)
        policy = {"allowed_schemas": ["visible"]}
        assert validate(db, allowed, policy)["allowed"], allowed
        result = validate(db, denied, policy)
        assert not result["allowed"] and result["code"] == "forbidden", (denied, result)


def test_generated_function_obfuscation(db):
    rng = random.Random(411)
    for _ in range(100):
        name = "".join(rng.choice([c.lower(), c.upper()]) for c in "md5")
        sql = rng.choice([
            f"SELECT {name} /* comment */ ('x')",
            f'SELECT "{name}"(\'x\')',
            f"SELECT main.{name}('x')",
            f"SELECT system.main.{name}('x')",
            f"SELECT CASE WHEN true THEN {name}('x') ELSE '' END",
        ])
        result = validate(db, sql, {"blocked_functions": ["md5"]})
        assert not result["allowed"] and result["code"] == "forbidden", (sql, result)


def test_vectorized_policy_overrides_and_nulls(db):
    db.execute("SELECT gatekeeper_configure('{\"blocked_functions\":[\"md5\"]}')")
    result = db.execute("""SELECT r.code, r.allowed, count(*) FROM (
        SELECT gatekeeper_validate(
            CASE WHEN i%3=0 THEN NULL ELSE 'SELECT md5(''x'')' END,
            CASE WHEN i%3=1 THEN '{"blocked_functions":[]}' ELSE '{}' END) r
        FROM range(12000) t(i)) GROUP BY ALL ORDER BY 1""").fetchall()
    assert result == [("forbidden", False, 4000), ("invalid_input", False, 4000), ("ok", True, 4000)]


def test_limits_at_edges_and_recovery(db):
    assert validate(db, "SELECT 1", {"limits": {"max_statements": 1}})["allowed"]
    assert not validate(db, "SELECT 1; SELECT 2", {"limits": {"max_statements": 1}})["allowed"]
    oversized = "SELECT '" + "x" * 1000 + "'"
    assert not validate(db, oversized, {"limits": {"max_ast_bytes": 100}})["allowed"]
    for _ in range(20):
        assert validate(db, "SELECT 1")["allowed"]
        assert not validate(db, "SELECT 1", {"limits": {"max_ast_nodes": 1}})["allowed"]
    for value in [0, -1, 0.5, True, None, "1", 2**64]:
        for key in ["max_statements", "max_ast_nodes", "max_ast_depth", "max_ast_bytes"]:
            result = validate(db, "SELECT 1", {"limits": {key: value}})
            assert not result["allowed"] and result["code"] == "invalid_input", (key, value, result)


def test_embedded_nul_policy_does_not_truncate(db):
    for key in ["allowed_functions", "blocked_functions", "allowed_schemas"]:
        policy = {key: ["md5\0suffix"]}
        result = validate(db, "SELECT md5('x')", policy)
        if key == "blocked_functions":
            assert result["allowed"]  # Exact length-aware name is distinct from md5.
        else:
            assert result["code"] in {"ok", "forbidden"}
    result = db.execute("SELECT gatekeeper_validate('SELECT 1', ?)", ['{"check_functions":false}\0{}']).fetchone()[0]
    assert not result["allowed"] and result["code"] == "invalid_input"
