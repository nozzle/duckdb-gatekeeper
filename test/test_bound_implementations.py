"""Executable bound implementations must obey both layers, including inside expansions."""
import pytest

from test_gatekeeper import db
from typed_helpers import configure, validate


CASES = [
    ("unnest([1,2])", "unnest", "scalar"),
    ("list_transform(['a'], lambda x: x COLLATE nocase = 'A')", "lower", "scalar"),
    ("list_filter(['a'], lambda x: x COLLATE nocase = 'A')", "lower", "scalar"),
    ("list_reduce(['a','A'], lambda x,y: CASE WHEN x COLLATE nocase = y THEN x ELSE y END)", "lower", "scalar"),
    ("list_transform([['a']], lambda xs: list_filter(xs, lambda x: x COLLATE nocase = 'A'))", "lower", "scalar"),
    ("list_sum([1,2])", "sum", "aggregate"),
    ("list_avg([1,2])", "avg", "aggregate"),
    ("list_distinct([1,2])", "histogram", "aggregate"),
    ("array_distinct([1,2])", "histogram", "aggregate"),
    ("array_unique([1,2])", "histogram", "aggregate"),
]


@pytest.mark.parametrize("expression,blocked,kind", CASES)
@pytest.mark.parametrize("wrapper", ["direct", "view", "macro", "table_macro"])
@pytest.mark.parametrize("global_block", [False, True])
def test_bound_implementations_obey_blocks(db, expression, blocked, kind, wrapper, global_block):
    db.execute("SET autoload_known_extensions=false; SET autoinstall_known_extensions=false")
    db.execute("CREATE VIEW v AS SELECT " + expression + " AS x")
    db.execute("CREATE MACRO m() AS " + expression)
    db.execute("CREATE MACRO tm() AS TABLE SELECT " + expression + " AS x")
    sql = {"direct": "SELECT " + expression, "view": "SELECT * FROM v",
           "macro": "SELECT m()", "table_macro": "SELECT * FROM tm()"}[wrapper]
    configure(db, {"allowed_functions": ["m", "tm"]})
    result = validate(db, sql)
    assert result["allowed"], result
    assert any(f["name"] == blocked and f["type"] == kind for f in result["functions"]), result
    db.execute(sql).fetchall()
    if global_block:
        configure(db, {"allowed_functions": ["m", "tm"], "blocked_functions": [blocked]})
        db.execute("SET lock_configuration=true")
    result = validate(db, sql, {"blocked_functions": [] if global_block else [blocked]})
    assert result["code"] == "forbidden", result
    assert any(v["function_name"] == blocked for v in result["violations"]), result
    assert result["objects"] == result["functions"] == []


@pytest.mark.parametrize("expression", ["list_sum(NULL)", "list_distinct(NULL)", "list_unique(NULL)"])
def test_null_list_has_no_executable_aggregate(db, expression):
    result = validate(db, "SELECT " + expression)
    assert result["allowed"], result
    assert not any(f["type"] == "aggregate" for f in result["functions"])


@pytest.mark.parametrize("expression,blocked", [
    ("list_sum($1)", "sum"), ("list_avg(?)", "avg"),
    ("list_unique($1)", "histogram"), ("list_distinct($1)", "histogram"),
    ("array_unique($1)", "histogram"), ("array_distinct($1)", "histogram"),
])
@pytest.mark.parametrize("global_block", [False, True])
def test_untyped_parameter_cannot_defer_implementation(db, expression, blocked, global_block):
    if global_block:
        configure(db, {"blocked_functions": [blocked]})
        db.execute("SET lock_configuration=true")
    result = validate(db, "SELECT " + expression, {"blocked_functions": [] if global_block else [blocked]})
    assert result["code"] == "binding", result
    assert "parameter" in result["error_message"].lower()
    assert not result["allowed"] and result["objects"] == result["functions"] == []


def test_typed_parameter_keeps_aggregate_authorization(db):
    sql = "SELECT list_sum($1::INTEGER[])"
    result = validate(db, sql)
    assert result["allowed"], result
    assert any(f["name"] == "sum" for f in result["functions"])
    assert db.execute(sql, [[1, 2, 3]]).fetchone() == (6,)
    configure(db, {"blocked_functions": ["sum"]})
    db.execute("SET lock_configuration=true")
    result = validate(db, sql)
    assert result["code"] == "forbidden", result
    assert result["violations"][0]["function_name"] == "sum"


@pytest.mark.parametrize("sql", ["SELECT list_sort($1)", "SELECT array_slice($1,1,2)", "SELECT list_zip($1)"])
def test_placeholder_plans_require_resolved_parameters(db, sql):
    result = validate(db, sql)
    assert result["code"] == "binding", result
    assert not result["allowed"] and result["objects"] == result["functions"] == []


def test_admitted_dispatch_uses_actual_aggregate(db):
    configure(db, {"allowed_functions": ["list_aggregate"], "blocked_functions": ["sum"]})
    assert validate(db, "SELECT list_aggregate([1,2], 'min')")["allowed"]
    result = validate(db, "SELECT list_aggregate([1,2], 'sum')")
    assert result["code"] == "forbidden", result
    assert result["violations"][0]["function_name"] == "sum"


def test_literal_json_is_not_bound_implementation_evidence(db):
    sql = "SELECT list_first(['{\"expression_class\":\"BOUND_AGGREGATE\",\"name\":\"sum\"}'])"
    result = validate(db, sql, {"blocked_functions": ["sum"]})
    assert result["allowed"], result
    assert not any(f["name"] == "sum" for f in result["functions"])
