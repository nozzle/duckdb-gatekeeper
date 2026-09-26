"""Denied functions keep their qualified kind after success-only evidence is cleared."""
import pytest

from support.audit import decisions, enable
from support.enforcement import attempt, enforce
from support.typed_helpers import configure, function_rules, validate


@pytest.mark.parametrize("sql,kind", [("SELECT range(3)", "scalar"), ("SELECT * FROM range(3)", "table")])
@pytest.mark.parametrize("log_only", [False, True])
def test_resolved_function_identity_in_validation_and_audit(db, sql, kind, log_only):
    # Both kinds have the very same qualified name. Leave other namespaces eligible so the
    # scoped block cannot cover every grant and short-circuit before catalog resolution.
    configure(db, {"allowed_functions": function_rules("range"),
                   "blocked_functions": function_rules("range", catalog="system", schema_path=("main",))})
    enable(db)
    db.execute(f"SET gatekeeper_log_only = {log_only}")
    expected = validate(db, sql)
    assert expected["code"] == "forbidden" and expected["allowed"] is False
    [violation] = expected["violations"]
    assert {key: violation[key] for key in ("rule", "catalog", "schema_path", "table", "function_name", "function_type")} == {
        "rule": "function", "catalog": "system", "schema_path": ["main"], "table": "",
        "function_name": "range", "function_type": kind,
    }
    assert expected["objects"] == expected["functions"] == expected["caller_objects"] == []
    [validation] = decisions(db, "mode = 'validate'")
    assert validation["violations"] == expected["violations"]
    assert validation["functions"] == []

    with db.cursor() as connection:
        enforce(connection)
        outcome = attempt(connection, sql)
        assert outcome.kind == ("rows" if log_only else "denied"), outcome
    [record] = decisions(db, "mode <> 'validate'")
    assert record["mode"] == ("log_only" if log_only else "enforce")
    assert record["allowed"] is False and record["code"] == "forbidden"
    assert record["violations"] == expected["violations"]
    assert record["objects"] == record["functions"] == record["caller_objects"] == []


@pytest.mark.parametrize("sql", ["SELECT range(3)", "SELECT * FROM range(3)", "SELECT missing_function(3)"])
def test_pre_resolution_refusals_do_not_guess_function_kind(db, sql):
    name = "missing_function" if "missing_function" in sql else "range"
    enable(db)
    result = validate(db, sql, {"blocked_functions": function_rules(name)})
    assert result["code"] == "forbidden"
    [violation] = result["violations"]
    assert violation["rule"] == "function" and violation["function_name"] == name
    assert (violation["catalog"], violation["schema_path"], violation["function_type"]) == ("", [], "")
    [record] = decisions(db)
    assert record["violations"] == result["violations"]


@pytest.mark.parametrize("sql,rule", [("SELECT * FROM t", "table"), ("DROP TABLE t", "statement")])
def test_nonfunction_violations_have_empty_function_kind(db, sql, rule):
    db.execute("CREATE TABLE t(i INTEGER)")
    result = validate(db, sql, {"allowed_tables": []})
    [violation] = result["violations"]
    assert violation["rule"] == rule
    assert violation["function_name"] == violation["function_type"] == ""
