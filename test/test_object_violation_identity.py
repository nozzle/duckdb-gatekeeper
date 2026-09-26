"""Denied catalog objects retain their actual kind in the public result and audit log."""
import pytest

from support.audit import decisions, enable
from support.artifact import ENGINE_MAJOR
from support.enforcement import attempt, enforce
from support.typed_helpers import configure, function_rules, validate


@pytest.mark.parametrize("kind", ["table", "view", pytest.param(
    "secure view", marks=pytest.mark.skipif(ENGINE_MAJOR < 2, reason="Secure views require DuckDB 2.0"))])
@pytest.mark.parametrize("blocked", [False, True])
@pytest.mark.parametrize("log_only", [False, True])
def test_resolved_object_identity_in_validation_and_audit(db, kind, blocked, log_only):
    # The same spelling is a table or a (secure) view: syntax and rule cannot tell them apart.
    db.execute('CREATE SCHEMA "Reporting.Path"')
    definition = "(i INTEGER)" if kind == "table" else "AS SELECT 1 AS i"
    db.execute(f'CREATE {kind} "Reporting.Path"."Orders" {definition}')
    object_rule = {"catalog": "memory", "schema_path": ["Reporting.Path"], "table": "Orders"}
    configure(db, {"blocked_tables": [object_rule]} if blocked else {"allowed_tables": []})
    enable(db)
    db.execute(f"SET gatekeeper_log_only = {log_only}")
    sql = 'SELECT * FROM "Reporting.Path"."Orders"'
    expected = validate(db, sql)
    assert expected["code"] == "forbidden" and expected["allowed"] is False
    [violation] = expected["violations"]
    assert violation == {
        "rule": "table", "message": "object is blocked" if blocked else "object is not allowed",
        **object_rule, "function_name": "", "position": None, "function_type": "",
        "object_type": "table" if kind == "table" else "view",
    }
    assert expected["objects"] == expected["functions"] == expected["caller_objects"] == []
    [validation] = decisions(db, "mode = 'validate'")
    assert validation["violations"] == expected["violations"]
    assert validation["objects"] == validation["functions"] == validation["caller_objects"] == []

    with db.cursor() as connection:
        enforce(connection)
        outcome = attempt(connection, sql)
        assert outcome.kind == ("rows" if log_only else "denied"), outcome
    [record] = decisions(db, "mode <> 'validate'")
    assert record["mode"] == ("log_only" if log_only else "enforce")
    assert record["allowed"] is False and record["code"] == "forbidden"
    assert record["violations"] == expected["violations"]
    assert record["objects"] == record["functions"] == record["caller_objects"] == []


@pytest.mark.parametrize("blocked", [False, True])
@pytest.mark.parametrize("log_only", [False, True])
def test_internal_view_identity_survives_denial(db, blocked, log_only):
    if blocked:
        configure(db, {"blocked_tables": [{"catalog": "system", "schema_path": ["main"], "table": "duckdb_tables"}]})
    enable(db)
    db.execute(f"SET gatekeeper_log_only = {log_only}")
    result = validate(db, "SELECT * FROM duckdb_tables")
    assert result["code"] == "forbidden" and result["allowed"] is False
    [violation] = result["violations"]
    assert violation["rule"] == ("table" if blocked else "internal_object")
    assert (violation["catalog"], violation["schema_path"], violation["table"], violation["object_type"]) == (
        "system", ["main"], "duckdb_tables", "view")
    assert violation["function_name"] == violation["function_type"] == ""
    with db.cursor() as connection:
        enforce(connection)
        assert attempt(connection, "SELECT * FROM duckdb_tables").kind == ("rows" if log_only else "denied")
    found = decisions(db)
    assert [record["mode"] for record in found] == ["validate", "log_only" if log_only else "enforce"]
    for record in found:
        assert record["violations"] == result["violations"]
        assert record["objects"] == record["functions"] == record["caller_objects"] == []


@pytest.mark.parametrize("sql,rule", [
    ("DROP TABLE missing", "statement"),
    ("SELECT 1; SELECT 2", "limit"),
    ("SELECT range(3)", "function"),
    ("SELECT * FROM '/nonexistent/gatekeeper.parquet'", "function"),
])
def test_unresolved_and_nonobject_violations_do_not_guess_object_kind(db, sql, rule):
    enable(db)
    result = validate(db, sql, {"blocked_functions": function_rules("range")})
    [violation] = result["violations"]
    assert violation["rule"] == rule
    assert violation["object_type"] == ""
    assert result["objects"] == result["functions"] == result["caller_objects"] == []
    [record] = decisions(db)
    assert record["violations"] == result["violations"]


def test_missing_object_is_a_binding_error_without_invented_identity(db):
    enable(db)
    result = validate(db, "SELECT * FROM missing_object", {"allowed_tables": []})
    assert result["code"] == "binding" and result["violations"] == []
    assert result["objects"] == result["functions"] == result["caller_objects"] == []
    [record] = decisions(db)
    assert record["violations"] == []
