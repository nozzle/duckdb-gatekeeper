"""Which violation is reported first when a statement could be denied for more than one reason.

The order is part of the contract the parity legs compare: gatekeeper_validate's violations, the message an
enforced connection refuses with, and the audit record must all name the same first denial. It follows from
where each check runs, not from a sort: the binding boundary collects every function denial in the text;
the private bind authorizes each catalog entry as the binder retrieves it, the ceiling before the request
layer; the execution boundary then walks the plan for tables and, only after, for bound functions, once per
layer with the ceiling first. These tests pin that order so a refactor of the authorization flow cannot
change it unnoticed.
"""
import pytest

from support.audit import decisions, enable
from support.enforcement import DENIED, attempt
from support.typed_helpers import configure, validate

REPORTING = {"schema": "reporting", "table": "*"}
SECRET = {"schema": "secret", "table": "*"}
SALARIES = {"schema": "secret", "table": "salaries"}


def first(result):
    violations = result["violations"]
    assert violations, result
    return violations[0]["rule"], violations[0]["message"], violations[0]["table"], violations[0]["function_name"]


def test_text_denials_are_all_reported_and_bind_denials_are_the_first_one(catalog):
    # Both names are denied by the text walk, so both are listed (sorted, as a set is).
    result = validate(catalog, "SELECT sha256('x'), md5('x')", {"blocked_functions": ["sha256"]})
    assert [v["function_name"] for v in result["violations"]] == ["md5", "sha256"]
    # A denial the bind finds stops at the first one.
    catalog.execute("CREATE TABLE secret.other(x INTEGER)")
    result = validate(catalog, "SELECT * FROM secret.salaries, secret.other")
    assert len(result["violations"]) == 1, result


@pytest.mark.parametrize("sql", [
    "SELECT list_aggregate([1], 'max') FROM secret.salaries",
    "SELECT list_aggregate([1], 'max') FROM secret.salaries WHERE amount > 0",
])
def test_table_denied_during_the_bind_precedes_a_function_denied_in_the_plan(catalog, agent, sql):
    # list_aggregate's target is chosen by a string the binder resolves, so it can only be denied on the bound
    # plan; the table is denied by the catalog callback while that plan is being bound, so it comes first.
    enable(catalog)
    configure(catalog, {"allowed_tables": [REPORTING], "allowed_functions": ["list_aggregate"],
                        "blocked_functions": ["max"]})
    expected = validate(catalog, sql)
    assert first(expected) == ("table", "object is not allowed", "salaries", "")
    seen = attempt(agent, sql)
    assert seen.kind == "denied" and "table: object is not allowed" in str(seen.error), seen
    assert "max" not in str(seen.error)
    [record] = decisions(catalog, "mode = 'enforce'")
    assert record["boundary"] == "authorize" and record["violations"] == expected["violations"]
    # The same function, with the table allowed, is the plan's denial.
    allowed_table = sql.replace("secret.salaries", "reporting.orders")
    assert first(validate(catalog, allowed_table)) == ("function", "dispatched aggregate is not allowed: max", "", "max")
    assert "dispatched aggregate is not allowed: max" in str(attempt(agent, allowed_table).error)


@pytest.mark.parametrize("sql", [
    "SELECT list_aggregate([1], 'max'), list_aggregate([1], 'min')",
    "SELECT list_aggregate([1], 'min'), list_aggregate([1], 'max')",
])
def test_the_ceiling_is_walked_before_the_request_layer(catalog, sql):
    # Two plan-level denials in one statement, one per layer: the ceiling's is reported whichever the text
    # names first, because the plan is walked once per layer and the ceiling's walk is the first.
    enable(catalog)
    configure(catalog, {"allowed_tables": [REPORTING], "allowed_functions": ["list_aggregate"],
                        "blocked_functions": ["max"]})
    expected = validate(catalog, sql, {"blocked_functions": ["min"]})
    assert first(expected) == ("function", "dispatched aggregate is not allowed: max", "", "max")
    [record] = decisions(catalog, "mode = 'validate'")
    assert record["violations"] == expected["violations"]
    # Only the request layer's denial remains once the ceiling allows the other name.
    configure(catalog, {"allowed_tables": [REPORTING], "allowed_functions": ["list_aggregate"]})
    assert first(validate(catalog, sql, {"blocked_functions": ["min"]})) == (
        "function", "dispatched aggregate is not allowed: min", "", "min")


@pytest.mark.parametrize("ceiling,options,message", [
    # The ceiling blocks the table and the request layer merely lacks a grant for it: the ceiling's rule and
    # message win because the ceiling is checked first.
    ({"allowed_tables": [REPORTING, SECRET], "blocked_tables": [SALARIES]}, {"allowed_tables": [REPORTING]},
     "object is blocked"),
    # The ceiling lacks the grant and the request layer blocks: still the ceiling's description.
    ({"allowed_tables": [REPORTING]}, {"blocked_tables": [SALARIES]}, "object is not allowed"),
])
def test_the_ceiling_describes_a_table_both_layers_deny(catalog, ceiling, options, message):
    enable(catalog)
    configure(catalog, ceiling)
    expected = validate(catalog, "SELECT * FROM secret.salaries", options)
    assert first(expected) == ("table", message, "salaries", "")
    [record] = decisions(catalog, "mode = 'validate'")
    assert record["violations"] == expected["violations"] and record["code"] == "forbidden"


def test_two_tables_are_denied_in_the_order_the_binder_retrieves_them(catalog):
    catalog.execute("CREATE TABLE secret.other(x INTEGER)")
    configure(catalog, {"allowed_tables": [REPORTING, SECRET], "blocked_tables": [SALARIES]})
    request = {"allowed_tables": [REPORTING]}
    assert first(validate(catalog, "SELECT * FROM secret.salaries, secret.other", request)) == (
        "table", "object is blocked", "salaries", "")
    assert first(validate(catalog, "SELECT * FROM secret.other, secret.salaries", request)) == (
        "table", "object is not allowed", "other", "")


def test_enforced_denials_name_the_same_first_violation_as_validate(catalog, agent):
    # The refusal message, the record and gatekeeper_validate agree on which denial came first.
    enable(catalog)
    catalog.execute("CREATE TABLE secret.other(x INTEGER)")
    for sql in ["SELECT * FROM secret.salaries, secret.other", "SELECT * FROM secret.other, secret.salaries"]:
        catalog.execute("CALL truncate_duckdb_logs()")
        expected = validate(catalog, sql)
        seen = attempt(agent, sql)
        assert seen.kind == "denied" and DENIED.search(str(seen.error))
        rule, message, table, _ = first(expected)
        assert f"{rule}: {message}" in str(seen.error)
        [record] = decisions(catalog, "mode = 'enforce'")
        assert record["violations"] == expected["violations"], (sql, record)
        assert record["violations"][0]["table"] == table == sql.split("secret.")[1].split(",")[0]
