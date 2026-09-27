"""Wrappers cannot erase caller replacement policy; 1.5 fails closed on mixed origins."""
import duckdb
import pytest

from support.artifact import ENGINE_MAJOR
from support.enforcement import enforce
from support.typed_helpers import configure, grants, validate


CASES = [
    ("min(x COLLATE nocase)", "arg_min", "VARCHAR", "'a'"),
    ("max(x COLLATE nocase)", "arg_max", "VARCHAR", "'a'"),
    ("min(x COLLATE nocase) OVER ()", "arg_min", "VARCHAR", "'a'"),
    ("max(x COLLATE nocase) OVER ()", "arg_max", "VARCHAR", "'a'"),
    ("date_part('epoch', x)", "epoch", "DOUBLE", "DATE '2020-01-01'"),
    ("datepart('julian', x)", "julian", "DOUBLE", "DATE '2020-01-01'"),
    ("quantile(x, 0.5)", "quantile_disc", "BIGINT", "1::BIGINT"),
    ("quantile(x, 0.5) OVER ()", "quantile_disc", "BIGINT", "1::BIGINT"),
]


@pytest.mark.parametrize("expression,target,typ,value", CASES)
@pytest.mark.parametrize("wrapper", ["cast", "coalesce", "macro", "nested"])
@pytest.mark.parametrize("ceiling", [False, True])
def test_wrappers_preserve_genuine_replacement_blocks(db, expression, target, typ, value, wrapper, ceiling):
    db.execute("CREATE MACRO passthrough(x) AS x")
    wrapped = {
        "cast": f"({expression})::{typ}",
        "coalesce": f"coalesce({expression}, NULL)",
        "macro": f"passthrough({expression})",
        "nested": f"passthrough(coalesce(({expression})::{typ}, NULL))",
    }[wrapper]
    sql = f"SELECT {wrapped} FROM (VALUES ({value})) t(x)"
    admitted = grants("passthrough", schema_path=("main",), type="macro")
    configure(db, {"allowed_functions": admitted})
    assert validate(db, sql)["allowed"], (sql, validate(db, sql))
    block = grants(target, schema_path=("main",))
    configure(db, {"allowed_functions": admitted, "blocked_functions": block if ceiling else []})
    result = validate(db, sql, {"blocked_functions": [] if ceiling else block})
    assert result["code"] == "forbidden", (sql, result)
    assert any(v["function_name"] == target for v in result["violations"]), result
    configure(db, {"allowed_functions": admitted, "blocked_functions": block})
    with db.cursor() as agent:
        enforce(agent)
        with pytest.raises(duckdb.PermissionException, match="Gatekeeper denied"):
            agent.execute(sql)


@pytest.mark.parametrize("source,target", [("min", "arg_min"), ("max", "arg_max")])
@pytest.mark.parametrize("host_macro", [False, True])
def test_mixed_trusted_replacement_is_conservative_only_on_15(db, source, target, host_macro):
    db.execute(f"CREATE VIEW trusted AS SELECT {target}(x,x) y FROM (VALUES ('a')) t(x)")
    db.execute(f"CREATE SCHEMA h; CREATE MACRO h.{source}(unused) AS (SELECT y FROM trusted)")
    configure(db, {"allowed_functions": grants(source, catalog="memory", schema_path=("h",), type="macro"),
                   "blocked_functions": grants(target, schema_path=("main",))})
    trusted = f"h.{source}(x)" if host_macro else "(SELECT y FROM trusted)"
    assert validate(db, f"SELECT system.main.{source}(x) FROM (VALUES ('a')) t(x)")["allowed"]
    assert validate(db, f"SELECT {trusted} FROM (VALUES ('a')) t(x)")["allowed"]
    for columns in [f"system.main.{source}(x), {trusted}", f"{trusted}, system.main.{source}(x)"]:
        sql = f"SELECT {columns} FROM (VALUES ('a')) t(x)"
        result = validate(db, sql)
        assert result["allowed"] is (ENGINE_MAJOR >= 2), (sql, result)
        with db.cursor() as agent:
            enforce(agent)
            if ENGINE_MAJOR >= 2:
                agent.execute(sql).fetchall()
            else:
                with pytest.raises(duckdb.PermissionException, match="Gatekeeper denied"):
                    agent.execute(sql)


@pytest.mark.parametrize("target", ["epoch", "julian", "year", "month", "day", "decade", "century",
                                    "millennium", "microsecond", "millisecond", "second", "minute", "hour",
                                    "dayofweek", "isodow", "week", "isoyear", "quarter", "dayofyear", "yearweek",
                                    "era", "timezone", "timezone_hour", "timezone_minute"])
def test_mixed_datepart_uses_retained_definition_on_20(db, target):
    db.execute(f"CREATE VIEW trusted AS SELECT {target}(TIMESTAMP '2020-01-01') y")
    configure(db, {"blocked_functions": grants(target, schema_path=("main",))})
    part = "julian" if target == "epoch" else "epoch"
    sql = f"SELECT date_part('{part}', TIMESTAMP '2020-01-01'), (SELECT y FROM trusted)"
    expected = ENGINE_MAJOR >= 2 or target not in {"epoch", "julian"}
    assert validate(db, sql)["allowed"] is expected, validate(db, sql)
