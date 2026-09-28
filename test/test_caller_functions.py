"""Caller evidence mirrors policy checks, including conservative engine attribution."""
import pytest

from support.artifact import by_engine
from support.corpus import CATALOG_POLICY, CATALOG_SQL, PARITY_CORPUS
from support.typed_helpers import configure, validate


def key(identity):
    return identity["catalog"], tuple(identity["schema_path"]), identity["name"], identity["type"]


def assert_preflight(result, names):
    assert result["code"] == "forbidden" and result["violations"], result
    for violation in result["violations"]:
        name = violation["function_name"]
        assert violation["rule"] == "function"
        assert violation["catalog"] == violation["function_type"] == ""
        assert violation["schema_path"] == []
        assert violation["message"] == f"function is not allowed: {name}"
        assert name in names, result


def assert_oracles(db, sql, options=None):
    options = options or {}
    result = validate(db, sql, options)
    callers = result["caller_functions"]
    assert list(map(key, callers)) == sorted(set(map(key, callers)))
    assert set(map(key, callers)) <= set(map(key, result["functions"]))
    if not result["allowed"]:
        assert callers == []
        return result
    replay = validate(db, sql, {**options, "use_default_functions": False, "allowed_functions": callers})
    if not replay["allowed"]:
        # Written-name preflight also checks functions in syntax the engine never binds.
        # Classify that structural limit; every identity-level replay failure is a bug.
        names = {v["function_name"] for v in replay["violations"]}
        assert_preflight(replay, names)
        assert not names & {f["name"].lower() for f in callers}, (sql, result, replay)
    for identity in result["functions"]:
        # Uncatalogued helpers cannot be expressed as exact policy rules (empty paths
        # are invalid). They must not receive caller-scoped authorization.
        if not identity["catalog"] or not identity["schema_path"]:
            assert identity not in callers
            continue
        rule = identity
        blocked = validate(db, sql, {**options, "blocked_functions": [*options.get("blocked_functions", []), rule]})
        if identity in callers:
            assert not blocked["allowed"], (sql, identity, result, blocked)
        elif not blocked["allowed"]:
            assert_preflight(blocked, {identity["name"].lower()})
    return result


@pytest.mark.parametrize("sql", PARITY_CORPUS)
def test_corpus_policy_oracles(db, sql):
    db.execute(CATALOG_SQL)
    db.execute("SET search_path = 'reporting,main'")
    configure(db, CATALOG_POLICY)
    assert_oracles(db, sql, CATALOG_POLICY)


@pytest.fixture
def functions_db(db):
    db.execute("CREATE TABLE t AS SELECT 1 x, 'A' s, ['a', 'b'] l")
    db.execute("CREATE MACRO m(a) AS a + length(sha256('trusted'))")
    db.execute("CREATE VIEW v AS SELECT md5(s) hashed, arg_min(x, s) OVER () am, x, s, l FROM t")
    configure(db, {"allowed_functions": [{"schema_path": ["main"], "name": "m"}]})
    return db


@pytest.mark.parametrize("sql", [
    "SELECT m(length(md5(s))) FROM t",
    "SELECT list_transform(l, lambda y: md5(y)) FROM t",
    "SELECT list_sum([1, 2])",
    "SELECT min(s COLLATE nocase) FROM t",
    "SELECT min(am) FROM v",
    "SELECT first(x) OVER () FROM t",
    "SELECT CAST(x AS VARCHAR) FROM t",
    "SELECT * FROM v",
    "SELECT md5(s), hashed FROM v",
    "SELECT quantile(x, 0.5), date_part('epoch', DATE '2020-01-01') FROM t",
    "WITH unused AS (SELECT md5(s) FROM t) SELECT 1",
    "WITH unused AS (SELECT md5(s) FROM t) SELECT hashed FROM v",
    "SELECT x FROM t WHERE false AND md5(s) = 'a'",
    "SELECT CASE WHEN false THEN md5(s) ELSE s END FROM t",
])
def test_function_paths(functions_db, sql):
    result = assert_oracles(functions_db, sql, {"allowed_functions": [{"schema_path": ["main"], "name": "m"}]})
    assert result["allowed"], result
    if "m(length" in sql or "list_transform" in sql:
        assert "md5" in {f["name"] for f in result["caller_functions"]}
    if "list_sum" in sql:
        assert {(f["name"], f["type"]) for f in result["caller_functions"]} >= {
            ("list_sum", "macro"), ("list_aggr", "scalar"), ("sum", "aggregate")}
    if sql == "SELECT min(am) FROM v":
        assert ("arg_min" in {f["name"] for f in result["caller_functions"]}) == by_engine(v1=True, v2=False)
    if "first(x)" in sql:
        assert {(f["name"], f["type"]) for f in result["caller_functions"]} == by_engine(
            v1={("first", "aggregate"), ("first_value", "window")}, v2={("first_value", "window")})
    assert "__cast" not in {f["name"] for f in result["caller_functions"]}
    if "unused" in sql and "SELECT 1" in sql:
        assert result["functions"] == result["caller_functions"] == []
    if "unused" in sql and "SELECT hashed" in sql:
        assert "md5" in {f["name"] for f in result["functions"]}
        assert "md5" not in {f["name"] for f in result["caller_functions"]}
    if "WHERE false" in sql or "CASE WHEN false" in sql:
        assert "md5" in {f["name"] for f in result["caller_functions"]}


def test_replacement_reader(db, tmp_path):
    path = str(tmp_path / "input.parquet").replace("'", "''")
    db.execute(f"COPY (SELECT 1 x) TO '{path}' (FORMAT PARQUET)")
    configure(db, {"allowed_functions": [{"catalog": "system", "schema_path": ["main"], "name": "parquet_scan"}]})
    result = assert_oracles(db, f"SELECT * FROM '{path}'", {
        "allowed_functions": [{"catalog": "system", "schema_path": ["main"], "name": "parquet_scan"}]})
    assert result["allowed"] and result["caller_objects"] == []
    assert "parquet_scan" in {f["name"] for f in result["caller_functions"]}


def test_prepared_validation(functions_db):
    functions_db.execute("PREPARE evidence AS SELECT caller_functions FROM gatekeeper_validate($1)")
    for sql in ["SELECT md5(s) FROM t", "SELECT * FROM v", "SELECT md5(s), hashed FROM v"]:
        expected = validate(functions_db, sql)["caller_functions"]
        literal = "'" + sql.replace("'", "''") + "'"
        assert functions_db.execute(f"EXECUTE evidence({literal})").fetchone()[0] == expected
