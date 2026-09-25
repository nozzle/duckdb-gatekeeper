"""Session-variable fallback, and the conservative pre-bind enforced collision gate."""
import json

import duckdb
import pytest

from support.artifact import ENGINE_MAJOR
from support.audit import decisions, enable
from support.enforcement import DENIED, enforce
from support.typed_helpers import configure, validate


V2 = pytest.mark.skipif(ENGINE_MAJOR < 2, reason="session-variable parameter fallback starts in DuckDB 2.0")
CAPABILITY = {"catalog": "system", "schema_path": ["main"], "name": "getvariable", "type": "scalar"}


@pytest.mark.skipif(ENGINE_MAJOR < 2, reason="session-variable fallback is a 2.0 capability")
@pytest.mark.parametrize("wrong", [
    {"catalog":"memory"}, {"schema_path":["host"]}, {"type":"table"},
])
def test_fallback_requires_exact_system_scalar_capability(db, wrong):
    db.execute("SET VARIABLE x = 42")
    configure(db, {"allowed_functions":[{**CAPABILITY, **wrong}]})
    assert validate(db, "SELECT $x")["code"] == "forbidden"


def test_ordinary_explicit_parameters_and_missing_inputs(db):
    configure(db, {"blocked_functions": ["getvariable"]})
    assert validate(db, "SELECT $missing")["code"] == "binding"
    assert validate(db, "SELECT * FROM range($missing)")["code"] == "binding"
    assert validate(db, "SELECT $missing::INTEGER")["allowed"]
    db.execute('SET VARIABLE "1" = 77')
    assert validate(db, "SELECT $1")["code"] == "binding"
    enforce(db)
    assert db.execute("SELECT $x", {"x": 7}).fetchall() == [(7,)]
    assert db.execute("SELECT $x::INTEGER", {"x": None}).fetchall() == [(None,)]
    assert db.execute("SELECT $1", [9]).fetchall() == [(9,)]


@pytest.mark.skipif(ENGINE_MAJOR >= 2, reason="1.5 has no implicit session-variable fallback")
def test_v1_collision_keeps_explicit_input_precedence(db):
    db.execute("SET VARIABLE x = 42")
    assert validate(db, "SELECT $x")["code"] == "binding"
    configure(db, {"blocked_functions": ["getvariable"]})
    enforce(db)
    assert db.execute("SELECT $x", {"x": 7}).fetchall() == [(7,)]


@V2
def test_fallback_requires_both_layers_and_records_fixed_identity(db):
    db.execute("SET VARIABLE x = 42")
    denied = validate(db, "SELECT $x")
    assert denied["code"] == "forbidden"
    assert denied["violations"][0]["catalog"] == "system"
    assert denied["violations"][0]["schema_path"] == ["main"]
    assert denied["violations"][0]["function_name"] == "getvariable"
    assert not validate(db, "SELECT $x", {"allowed_functions": [CAPABILITY]})["allowed"]
    configure(db, {"use_default_functions": False, "allowed_functions": [CAPABILITY]})
    # A host shadow is not the capability that the engine uses for $x.
    db.execute("CREATE MACRO main.getvariable(n) AS 999")
    result = validate(db, "SELECT $x, $X")
    assert result["allowed"] and result["functions"] == [CAPABILITY], result
    for options in [{"allowed_functions": []}, {"blocked_functions": ["getvariable"]}]:
        assert validate(db, "SELECT $x", options)["code"] == "forbidden"
    db.execute("SET VARIABLE x = NULL")
    assert validate(db, "SELECT $x")["functions"] == [CAPABILITY]
    configure(db, {"allowed_functions": [CAPABILITY], "blocked_functions": ["getvariable"]})
    assert validate(db, "SELECT $x")["code"] == "forbidden"


@V2
@pytest.mark.parametrize("sql", [
    "SELECT * FROM range($x)", "SELECT 1 LIMIT $x", "SELECT 1 OFFSET $x",
    "SELECT * FROM missing AT (VERSION => $x)",
    "SELECT COLUMNS($x) FROM missing", "PIVOT missing ON n IN ($x) USING sum(n)",
])
def test_fallback_guard_wins_before_bind_time_sites(db, sql):
    db.execute("SET VARIABLE x = 'DO_NOT_DISCLOSE_SENTINEL['")
    result = validate(db, sql)
    assert result["code"] == "forbidden", result
    assert {v["function_name"] for v in result["violations"]} == {"getvariable"}, result
    assert "DO_NOT_DISCLOSE" not in json.dumps(result)
    assert result["functions"] == result["objects"] == []
    enforce(db)
    with pytest.raises(duckdb.Error, match="supplied-value provenance"):
        db.execute(sql)


@V2
def test_allowed_bind_time_fallbacks(db):
    configure(db, {"allowed_functions": [CAPABILITY]})
    db.execute("CREATE TABLE t AS SELECT 1 x; SET VARIABLE n = 1; SET VARIABLE cols = ['x']")
    for sql in ["SELECT * FROM range($n)", "SELECT * FROM t LIMIT $n OFFSET $n",
                "SELECT COLUMNS($cols) FROM t", "PIVOT t ON x IN ($n) USING sum(x)"]:
        result = validate(db, sql)
        assert result["allowed"] and CAPABILITY in result["functions"], result
    assert validate(db, "SELECT * FROM t TABLESAMPLE reservoir($n ROWS)")["code"] == "parser"


@V2
@pytest.mark.parametrize("allowed", [False, True])
@pytest.mark.parametrize("explicit", [False, True])
def test_enforcement_refuses_ambiguous_collision_even_when_allowed_or_explicit(db, allowed, explicit):
    db.execute("SET VARIABLE x = 42")
    configure(db, {"allowed_functions": [CAPABILITY]} if allowed else {})
    enforce(db)
    with pytest.raises(duckdb.Error, match="supplied-value provenance"):
        db.execute("SELECT $X", {"X": 7} if explicit else None)
    assert db.execute("SELECT $other", {"other": 8}).fetchall() == [(8,)]


@V2
def test_trusted_view_is_not_a_caller_reference(db):
    db.execute("SET VARIABLE x = 42; CREATE VIEW v AS SELECT $x AS n")
    db.execute("CREATE MACRO m(a) AS a")
    configure(db, {"allowed_functions": [{"schema_path":["main"],"name":"m","type":"macro"}], "blocked_functions": ["getvariable"]})
    assert validate(db, "SELECT * FROM v")["allowed"]
    assert validate(db, "SELECT m($x)")["code"] == "forbidden"
    assert validate(db, "SELECT $x FROM v")["code"] == "forbidden"
    enforce(db)
    assert db.execute("SELECT * FROM v").fetchall() == [(42,)]
    with pytest.raises(duckdb.Error, match=DENIED):
        db.execute("SELECT $x FROM v")


@V2
def test_variable_and_policy_changes_rechecked_in_validation(db):
    configure(db, {"allowed_functions": [CAPABILITY]})
    assert validate(db, "SELECT $x")["code"] == "binding"
    db.execute("SET VARIABLE x = 1")
    assert validate(db, "SELECT $x")["functions"] == [CAPABILITY]
    db.execute("SET VARIABLE x = 2")
    configure(db, {"blocked_functions": ["getvariable"]})
    assert validate(db, "SELECT $x")["code"] == "forbidden"
    db.execute("RESET VARIABLE x")
    assert validate(db, "SELECT $x")["code"] == "binding"


@V2
def test_binding_errors_do_not_record_variable_values(db):
    db.execute("CREATE TABLE t(x INT); SET VARIABLE regex = 'PRIVATE_SENTINEL['")
    configure(db, {"allowed_functions": [CAPABILITY]})
    enable(db)
    result = validate(db, "SELECT COLUMNS($regex) FROM t")
    assert result["code"] == "binding" and "details suppressed" in result["error_message"]
    assert "PRIVATE_SENTINEL" not in json.dumps(result)
    assert "PRIVATE_SENTINEL" not in json.dumps(decisions(db))


@V2
def test_trusted_fallback_binding_error_is_also_redacted(db):
    db.execute("CREATE TABLE t(x INT); SET VARIABLE regex = 'x'")
    db.execute("CREATE VIEW v AS SELECT COLUMNS($regex) FROM t")
    db.execute("SET VARIABLE regex = 'TRUSTED_SENTINEL['")
    enable(db)
    result = validate(db, "SELECT * FROM v")
    assert result["code"] == "binding" and "details suppressed" in result["error_message"]
    assert "TRUSTED_SENTINEL" not in json.dumps(result)
    assert "TRUSTED_SENTINEL" not in json.dumps(decisions(db))


@V2
@pytest.mark.parametrize("explicit,expected", [(False, 42), (True, 7)])
def test_log_only_records_ambiguity_once_per_statement_without_refusing(db, explicit, expected):
    enable(db)
    db.execute("SET gatekeeper_log_only = true")
    with db.cursor() as agent:
        agent.execute("SET VARIABLE x = 42")
        enforce(agent)
        assert agent.execute("SELECT $x", {"x": 7} if explicit else None).fetchall() == [(expected,)]
    found = decisions(db, "mode = 'log_only' AND statement = 'SELECT $x'")
    # Some clients prepare and execute as separate internal statements with the same text.
    assert found and len({r["query_id"] for r in found}) == len(found), found
    if not explicit:
        assert len(found) == 1, found
    for record in found:
        assert not record["allowed"] and record["boundary"] == "binding"
        assert "supplied-value provenance" in record["violations"][0]["message"]
        assert record["functions"] == []
