"""Source-derived implementations retain the origin of the function that selected them."""
import pytest

from support.enforcement import DENIED, enforce
from support.audit import enable, decisions
from support.artifact import ENGINE_MAJOR
from support.typed_helpers import configure, validate


def identity(name, kind="aggregate", catalog="system", schema="main"):
    return {"catalog": catalog, "schema_path": [schema], "name": name, "type": kind}


CASES = [
    ("min(x COLLATE nocase)", "arg_min", "aggregate", "'a'"),
    ("max(x COLLATE nocase)", "arg_max", "aggregate", "'a'"),
    ("date_part('epoch', x)", "epoch", "scalar", "DATE '2020-01-01'"),
    ("datepart('julian', x)", "julian", "scalar", "DATE '2020-01-01'"),
    ("quantile(x, 0.5)", "quantile_disc", "aggregate", "1"),
    ("quantile(x, [0.5])", "quantile_disc", "aggregate", "1"),
]


@pytest.mark.parametrize("expression,target,kind,value", CASES)
@pytest.mark.parametrize("global_block", [False, True])
def test_substitutions_keep_caller_origin(db, expression, target, kind, value, global_block):
    enable(db)
    sql = f"SELECT {expression} FROM (VALUES ({value})) t(x)"
    db.execute(f"CREATE MACRO wrapper() AS ({sql})")
    db.execute(f"CREATE VIEW wrapped AS {sql}")
    grants = {"allowed_functions": [identity("wrapper", "macro", "memory")]}
    block = {"blocked_functions": [identity(target, kind)]}
    configure(db, {**grants, **(block if global_block else {})})
    request = {} if global_block else block
    result = validate(db, sql, request)
    assert result["code"] == "forbidden", result
    assert any(v["function_name"] == target for v in result["violations"]), result
    for trusted in ("SELECT wrapper()", "SELECT * FROM wrapped"):
        assert validate(db, trusted, request)["allowed"], validate(db, trusted, request)
    for mixed in (f"SELECT wrapper(), {expression} FROM (VALUES ({value})) t(x)",
                  f"SELECT {expression}, wrapper() FROM (VALUES ({value})) t(x)"):
        assert validate(db, mixed, request)["code"] == "forbidden"
    configure(db, {**grants, **block})
    with db.cursor() as agent:
        enforce(agent)
        with pytest.raises(Exception, match=DENIED):
            agent.execute(sql)
        agent.execute("SELECT wrapper()").fetchall()
        db.execute("SET GLOBAL gatekeeper_log_only=true")
        agent.execute(sql).fetchall()
    records = decisions(db)
    assert any(r.get("statement") == sql and r.get("code") == "forbidden"
               and r.get("mode") == "log_only" for r in records), records


@pytest.mark.parametrize("expression,target,kind,value", CASES)
def test_substitutions_require_strict_implementation_grants(db, expression, target, kind, value):
    source = expression.split("(")[0]
    grants = [identity(source, kind)]
    if "COLLATE" in expression:
        grants.append(identity("lower", "scalar"))
    if "[" in expression:
        grants.append(identity("list_value", "scalar"))
    options = {"use_default_functions": False, "allowed_functions": grants}
    configure(db, options)
    sql = f"SELECT {expression} FROM (VALUES ({value})) t(x)"
    assert validate(db, sql)["code"] == "forbidden"
    grants.append(identity(target, kind))
    configure(db, options)
    result = validate(db, sql)
    assert result["allowed"], result
    assert identity(target, kind) in result["functions"], result


@pytest.mark.parametrize("name", ["quantile", "quantile_disc", "quantile_cont", "approx_quantile", "reservoir_quantile"])
def test_quantile_contract_only_applies_to_system_aggregate(db, name):
    db.execute(f"CREATE SCHEMA host; CREATE MACRO host.{name}(x, q) AS x + q")
    configure(db, {"allowed_functions": [identity(name, "macro", "memory", "host")]})
    sql = f"SELECT host.{name}(x, x + 1) FROM (VALUES (1)) t(x)"
    assert validate(db, sql)["allowed"], validate(db, sql)
    for sql in (f"SELECT {name}(x, 0.25 + 0.25) FROM (VALUES (1)) t(x)",
                f"SELECT x.{name}(0.25 + 0.25) FROM (VALUES (1)) t(x)"):
        result = validate(db, sql)
        assert result["code"] == "forbidden", result
        assert any(v["rule"] == "bind_time_expression" for v in result["violations"]), result


@pytest.mark.parametrize("caller,body", [("read_parquet", "parquet_scan"), ("parquet_scan", "read_parquet")])
def test_host_alias_does_not_attribute_trusted_reader(db, tmp_path, caller, body):
    path = str(tmp_path / "data.parquet").replace("'", "''")
    db.execute(f"COPY (SELECT 1 x) TO '{path}' (FORMAT PARQUET)")
    db.execute(f"CREATE MACRO {caller}() AS 7")
    db.execute(f"CREATE MACRO wrapper() AS (SELECT x FROM {body}('{path}'))")
    configure(db, {"allowed_functions": [identity(n, "macro", "memory") for n in (caller, "wrapper")],
                   "blocked_functions": [identity("read_parquet", "table")]})
    for sql in (f"SELECT {caller}(), wrapper()", f"SELECT wrapper(), {caller}()"):
        result = validate(db, sql)
        assert result["allowed"], result


# All valid DatePartSpecifier members, including DatePartUnaryFunctionName's
# exceptional spellings. The 1.5 binder only substitutes epoch and julian.
DATE_PARTS = [
    ("year", "year"), ("month", "month"), ("day", "day"), ("decade", "decade"),
    ("century", "century"), ("millennium", "millennium"),
    ("microseconds", "microsecond"), ("milliseconds", "millisecond"),
    ("second", "second"), ("minute", "minute"), ("hour", "hour"),
    ("dow", "dayofweek"), ("isodow", "isodow"), ("week", "week"),
    ("isoyear", "isoyear"), ("quarter", "quarter"), ("doy", "dayofyear"),
    ("yearweek", "yearweek"), ("era", "era"), ("timezone", "timezone"),
    ("timezone_hour", "timezone_hour"), ("timezone_minute", "timezone_minute"),
    ("epoch", "epoch"), ("julian", "julian"),
]


@pytest.mark.parametrize("part,target", DATE_PARTS)
@pytest.mark.parametrize("source", ["date_part", "datepart"])
def test_every_date_part_substitution(db, part, target, source):
    sql = f"SELECT {source}('{part}', TIMESTAMP '2020-06-15 12:34:56.123456')"
    db.execute(f"CREATE MACRO wrapper() AS ({sql})")
    db.execute(f"CREATE VIEW wrapped AS {sql}")
    grants = [identity("wrapper", "macro", "memory")]
    configure(db, {"allowed_functions": grants})
    substituted = ENGINE_MAJOR >= 2 or part in ("epoch", "julian")
    block = {"blocked_functions": [identity(target, "scalar")]}
    result = validate(db, sql, block)
    assert result["allowed"] == (not substituted), result
    if substituted:
        assert any(v["function_name"] == target for v in result["violations"]), result
    for trusted in ("SELECT wrapper()", "SELECT * FROM wrapped"):
        assert validate(db, trusted, block)["allowed"], (trusted, validate(db, trusted, block))
    configure(db, {"allowed_functions": grants, **block})
    with db.cursor() as agent:
        enforce(agent)
        if substituted:
            with pytest.raises(Exception, match=DENIED):
                agent.execute(sql)
        else:
            agent.execute(sql).fetchall()
        agent.execute("SELECT wrapper()").fetchall()
    strict = {"use_default_functions": False, "allowed_functions": [identity(source, "scalar")]}
    configure(db, strict)
    result = validate(db, sql)
    assert result["allowed"] == (not substituted), result
    strict["allowed_functions"].append(identity(target, "scalar"))
    configure(db, strict)
    result = validate(db, sql)
    assert result["allowed"], result
    if substituted:
        assert identity(target, "scalar") in result["functions"], result


@pytest.mark.skipif(ENGINE_MAJOR < 2, reason="named builtin signature reordering is a 2.0 API")
@pytest.mark.parametrize("name", ["quantile", "quantile_disc", "quantile_cont", "approx_quantile", "reservoir_quantile"])
@pytest.mark.parametrize("window", ["", " OVER ()"])
def test_named_quantile_mappings_are_conservatively_refused(db, name, window):
    sql = f"SELECT {name}(quantile := 0.5, x := 1){window}"
    result = validate(db, sql)
    assert result["code"] == "forbidden", result
    assert any(v["rule"] == "bind_time_expression" for v in result["violations"]), result


@pytest.mark.parametrize("name", ["quantile", "quantile_disc", "quantile_cont", "approx_quantile", "reservoir_quantile",
                                  "list_aggregate", "list_aggr", "array_aggregate", "array_aggr", "aggregate"])
def test_named_contract_does_not_restrict_host_macros(db, name):
    db.execute(f"CREATE SCHEMA host; CREATE MACRO host.{name}(x, q) AS x + q")
    configure(db, {"allowed_functions": [identity(name, "macro", "memory", "host")]})
    sql = f"SELECT host.{name}(q := x + 1, x := x) FROM (VALUES (1)) t(x)"
    result = validate(db, sql)
    assert result["allowed"], result
