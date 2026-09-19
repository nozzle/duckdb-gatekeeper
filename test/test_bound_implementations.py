"""Executable bound implementations obey both layers where the caller wrote them; inside a trusted definition
they are that definition's own, outside function policy altogether."""
import duckdb
import json

import pytest

from support.artifact import ROOT
from support.enforcement import DENIED, enforce
from support.headers import header_names
from support.typed_helpers import configure, validate


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
WRAPPERS = {"view": "SELECT * FROM v", "macro": "SELECT m()", "table_macro": "SELECT * FROM tm()"}


@pytest.mark.parametrize("expression,blocked,kind", CASES)
@pytest.mark.parametrize("global_block", [False, True])
def test_bound_implementations_obey_blocks_where_the_caller_wrote_them(db, expression, blocked, kind, global_block):
    """The implementation DuckDB binds for a caller-written expression (the collation's lower, the dispatched
    aggregate, unnest) is the caller's, and blocks in either layer reach it. The same expression inside a host
    view, scalar macro, or table macro is that definition's own: exempt from blocks like the rest of its body,
    still reported in the dependency list. Writing the expression next to the wrapper makes the implementation
    the caller's again, query-wide."""
    db.execute("SET autoload_known_extensions=false; SET autoinstall_known_extensions=false")
    db.execute("CREATE VIEW v AS SELECT " + expression + " AS x")
    db.execute("CREATE MACRO m() AS " + expression)
    db.execute("CREATE MACRO tm() AS TABLE SELECT " + expression + " AS x")
    direct = "SELECT " + expression
    configure(db, {"allowed_functions": ["m", "tm"]})
    for sql in [direct, *WRAPPERS.values()]:
        result = validate(db, sql)
        assert result["allowed"], (sql, result)
        assert any(f["name"] == blocked and f["type"] == kind for f in result["functions"]), (sql, result)
        db.execute(sql).fetchall()
    if global_block:
        configure(db, {"allowed_functions": ["m", "tm"], "blocked_functions": [blocked]})
        db.execute("SET lock_configuration=true")
    layer = {"blocked_functions": [] if global_block else [blocked]}
    result = validate(db, direct, layer)
    assert result["code"] == "forbidden", result
    assert any(v["function_name"] == blocked for v in result["violations"]), result
    assert result["objects"] == result["functions"] == []
    for wrapper, sql in WRAPPERS.items():
        result = validate(db, sql, layer)
        assert result["allowed"], (wrapper, result)
        assert any(f["name"] == blocked and f["type"] == kind for f in result["functions"]), (wrapper, result)
    result = validate(db, direct + " FROM v", layer)
    assert result["code"] == "forbidden", result
    assert any(v["function_name"] == blocked for v in result["violations"]), result


@pytest.mark.parametrize("expression", ["list_sum(NULL)", "list_distinct(NULL)", "list_unique(NULL)"])
def test_null_list_has_no_executable_aggregate(db, expression):
    result = validate(db, "SELECT " + expression)
    assert result["allowed"], result
    assert not any(f["type"] == "aggregate" for f in result["functions"])


@pytest.mark.parametrize("order", ["macro_first", "caller_first"])
def test_trusted_macro_body_does_not_launder_caller_expansions(db, order):
    """A host scalar macro body binds in the caller's own binder, so its names are recognized by name. The
    caller's text can reach the same implementation without naming it, through a default macro it expands to
    (list_count names list_aggr); that expansion is the caller's, in either order, and the aggregate it
    dispatches stays subject to the caller's blocks. The host macro's own dispatch stays its own."""
    db.execute("CREATE MACRO m() AS list_sum([1,2])")
    configure(db, {"allowed_functions": ["m"], "blocked_functions": ["count"]})
    mixed = "SELECT m(), list_count([3])" if order == "macro_first" else "SELECT list_count([3]), m()"
    for sql in ["SELECT list_count([3])", mixed]:
        result = validate(db, sql)
        assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "count", (sql, result)
    assert validate(db, "SELECT m()")["allowed"]
    assert validate(db, "SELECT m()", {"blocked_functions": ["sum", "list_aggr", "list_sum"]})["allowed"]
    # Blocking the shared dispatcher itself reaches the caller's expansion and, since the name is then the
    # caller's query-wide, the macro's use in the same statement; the macro alone is untouched.
    assert validate(db, mixed.replace("list_count([3])", "list_avg([3])"), {"blocked_functions": ["list_aggr"]})["code"] == "forbidden"
    assert validate(db, "SELECT m()", {"blocked_functions": ["list_aggr"]})["allowed"]
    with db.cursor() as agent:
        enforce(agent)
        assert agent.execute("SELECT m()").fetchone() == (3,)
        for sql, parameters in [(mixed, None), (mixed.replace("[3]", "[?]"), [3])]:
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute(sql, parameters).fetchall()


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
    """Fixed implementations and dispatchers introduced only by trusted definitions are those definitions' own;
    once the caller writes a dispatcher, the allowlist check applies query-wide like other ambiguous caller
    syntax."""
    db.execute("CREATE VIEW v AS SELECT list_aggregate([1,2], 'sum') AS s")
    configure(db, {**STRICT, "allowed_functions": STRICT["allowed_functions"] + ["count"]})
    assert validate(db, "SELECT list_distinct([1,2])", STRICT)["allowed"]
    assert validate(db, "SELECT s FROM v", STRICT)["allowed"]
    # The view's dispatched aggregate is the view's: a block on it does not reach into the body.
    assert validate(db, "SELECT s FROM v", {**STRICT, "blocked_functions": ["sum"]})["allowed"]
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


LAMBDA_CALLS = {
    "list_transform": "{f}(['a'], lambda x: x COLLATE nocase = 'A')",
    "array_transform": "{f}(['a'], lambda x: x COLLATE nocase = 'A')",
    "list_apply": "{f}(['a'], lambda x: x COLLATE nocase = 'A')",
    "array_apply": "{f}(['a'], lambda x: x COLLATE nocase = 'A')",
    "apply": "{f}(['a'], lambda x: x COLLATE nocase = 'A')",
    "list_filter": "{f}(['a'], lambda x: x COLLATE nocase = 'A')",
    "array_filter": "{f}(['a'], lambda x: x COLLATE nocase = 'A')",
    "filter": "{f}(['a'], lambda x: x COLLATE nocase = 'A')",
    "list_reduce": "{f}(['a','A'], lambda x, y: CASE WHEN x COLLATE nocase = y THEN x ELSE y END)",
    "array_reduce": "{f}(['a','A'], lambda x, y: CASE WHEN x COLLATE nocase = y THEN x ELSE y END)",
    "reduce": "{f}(['a','A'], lambda x, y: CASE WHEN x COLLATE nocase = y THEN x ELSE y END)",
}


def test_list_lambda_function_names_match_the_engine():
    """The fail-closed lambda inspection covers exactly DuckDB's list-lambda builtins and their aliases, so a
    renamed or added alias in the engine cannot leave a lambda body uninspected without failing this test."""
    source = ROOT / "duckdb/extension/core_functions/scalar/list/functions.json"
    if not source.is_file():
        pytest.skip("engine source checkout not present (distributed-artifact test run)")
    functions = json.loads(source.read_text())
    engine = set()
    for entry in functions:
        if entry["name"] in ("list_transform", "list_filter", "list_reduce"):
            engine.add(entry["name"])
            engine.update(entry.get("aliases", []))
    assert header_names("ListLambdaFunctions") == engine == set(LAMBDA_CALLS)
    dispatchers = set()
    for entry in functions:
        if entry["name"] in ("list_aggregate",):
            dispatchers.add(entry["name"])
            dispatchers.update(entry.get("aliases", []))
    assert header_names("DispatchingAggregators") == dispatchers


@pytest.mark.parametrize("function", sorted(LAMBDA_CALLS))
def test_every_list_lambda_alias_exposes_its_body(db, function):
    """Each alias binds ListLambdaBindData and its body is walked: the nocase comparison inside binds `lower`,
    which is reported directly and through a trusted view, and blockable where the caller wrote it."""
    expression = LAMBDA_CALLS[function].format(f=function)
    db.execute("CREATE VIEW v AS SELECT " + expression + " AS x")
    for sql in ("SELECT " + expression, "SELECT * FROM v"):
        result = validate(db, sql)
        assert result["allowed"], result
        assert any(f["name"] == "lower" for f in result["functions"]), result
    result = validate(db, "SELECT " + expression, {"blocked_functions": ["lower"]})
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "lower", result
    assert validate(db, "SELECT * FROM v", {"blocked_functions": ["lower"]})["allowed"]
    # A NULL list still binds the builtin with an empty body; nothing to inspect, nothing to deny.
    assert validate(db, f"SELECT {function}(NULL, lambda x: x)" if "reduce" not in function
                    else f"SELECT {function}(NULL, lambda x, y: x)")["allowed"]
