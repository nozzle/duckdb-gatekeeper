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


STRICT = {"use_default_functions": False,
          "allowed_functions": ["list_aggregate", "list_aggr", "aggregate", "array_aggregate", "array_aggr",
                                "list_value", "list_distinct"]}


@pytest.mark.parametrize("dispatcher", ["list_aggregate", "list_aggr", "aggregate", "array_aggregate", "array_aggr"])
def test_caller_written_dispatch_target_must_be_allowed(db, dispatcher):
    """The aggregate a caller selects by name is caller-chosen text: a strict allowlist that admits only the
    dispatcher must not reach every unblocked aggregate. Folding the name does not evade the bound check."""
    configure(db, {**STRICT, "allowed_functions": STRICT["allowed_functions"] + ["sum", "||"]})
    concat = {**STRICT, "allowed_functions": STRICT["allowed_functions"] + ["||"]}
    for name in ("'sum'", "'su' || 'm'"):
        result = validate(db, f"SELECT {dispatcher}([1,2], {name})", concat)
        assert result["code"] == "forbidden", result
        assert result["violations"][0]["rule"] == "function" and result["violations"][0]["function_name"] == "sum", result
    granted = {**concat, "allowed_functions": concat["allowed_functions"] + ["sum"]}
    result = validate(db, f"SELECT {dispatcher}([1,2], 'su' || 'm')", granted)
    assert result["allowed"], result
    assert any(f["name"] == "sum" and f["type"] == "aggregate" for f in result["functions"]), result
    # Both layers must grant the target: the request cannot add it past the global ceiling.
    configure(db, STRICT)
    assert validate(db, f"SELECT {dispatcher}([1,2], 'sum')", granted)["code"] == "forbidden"


def test_dispatch_target_check_is_scoped_to_caller_written_dispatchers(db):
    """Fixed implementations and dispatchers introduced only by trusted definitions keep the block-only rule;
    once the caller writes a dispatcher, the check applies query-wide like other ambiguous caller syntax."""
    db.execute("CREATE VIEW v AS SELECT list_aggregate([1,2], 'sum') AS s")
    configure(db, {**STRICT, "allowed_functions": STRICT["allowed_functions"] + ["count"]})
    assert validate(db, "SELECT list_distinct([1,2])", STRICT)["allowed"]
    assert validate(db, "SELECT s FROM v", STRICT)["allowed"]
    assert validate(db, "SELECT s FROM v", {**STRICT, "blocked_functions": ["sum"]})["code"] == "forbidden"
    request = {**STRICT, "allowed_functions": STRICT["allowed_functions"] + ["count"]}
    assert validate(db, "SELECT list_aggregate([1], 'count')", request)["allowed"]
    # The view's own dispatch is bound into the same plan, so the caller's dispatcher makes it subject to the check.
    result = validate(db, "SELECT list_aggregate([1], 'count') FROM v", request)
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "sum", result
    # With defaults on, an admitted dispatcher reaches default aggregates but not elevated ones.
    configure(db, {"allowed_functions": ["list_aggregate"]})
    assert validate(db, "SELECT list_aggregate([1,2], 'sum')")["allowed"]
    result = validate(db, "SELECT list_aggregate([1,2], 'histogram')")
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "histogram", result
