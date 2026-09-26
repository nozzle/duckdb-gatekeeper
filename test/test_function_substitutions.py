"""Source-derived implementations retain the origin of the function that selected them."""
import pytest

from support.enforcement import DENIED, enforce
from support.audit import enable, decisions
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
