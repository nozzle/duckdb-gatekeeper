"""Deterministic generated combinations with independently specified outcomes."""
import random

from support.typed_helpers import configure, validate


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
        policy = {"allowed_tables": [{"catalog": "*", "schema_path": ["visible"], "table": "*"}]}
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


def test_prepared_policy_overrides_and_nulls(db):
    configure(db,{"blocked_functions":["md5"]})
    for sql, blocks, code in [(None, ["md5"], "invalid_input"),
                              ("SELECT md5('x')", [], "forbidden"),
                              ("SELECT md5('x')", ["md5"], "forbidden")]:
        result = db.execute("SELECT code, allowed FROM gatekeeper_validate(?, blocked_functions := ?)",
                            [sql, blocks]).fetchall()
        assert result == [(code, False)]


def test_limits_at_edges_and_recovery(db):
    for _ in range(20):
        assert validate(db, "SELECT 1")["allowed"]
        assert not validate(db, "SELECT 1; SELECT 2")["allowed"]


def test_embedded_nul_policy_does_not_truncate(db):
    for key in ["allowed_functions", "blocked_functions"]:
        policy = {key: ["md5\0suffix"]}
        result = validate(db, "SELECT md5('x')", policy)
        assert result["code"] == "invalid_input"
    for field in ["catalog", "schema_path", "table"]:
        entry = {"catalog": "*", "schema_path": ["main"], "table": "*",
                 field: ["name\0suffix"] if field == "schema_path" else "name\0suffix"}
        assert validate(db, "SELECT 1", {"allowed_tables": [entry]})["code"] == "invalid_input"
