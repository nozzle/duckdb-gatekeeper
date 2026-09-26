"""Only a selected binder replacement can acquire caller ownership."""
import pytest
import duckdb

from support.artifact import ENGINE_MAJOR
from support.enforcement import enforce
from support.typed_helpers import configure, grants, validate


@pytest.mark.parametrize("source,target", [("min", "arg_min"), ("max", "arg_max")])
@pytest.mark.parametrize("wrapper", ["view", "macro"])
def test_plain_aggregate_does_not_claim_trusted_replacement(db, source, target, wrapper):
    db.execute(f"CREATE VIEW trusted AS SELECT {target}(x,x) y FROM (VALUES ('a'),('b')) t(x)")
    db.execute("CREATE MACRO trusted_macro() AS (SELECT y FROM trusted)")
    configure(db, {"allowed_functions": grants("trusted_macro", schema_path=("main",)),
                   "blocked_functions": grants(target, schema_path=("main",))})
    trusted = "(SELECT y FROM trusted)" if wrapper == "view" else "trusted_macro()"
    for values in (f"{source}(x), {trusted}", f"{trusted}, {source}(x)"):
        sql = f"SELECT {values} FROM (VALUES ('a'),('b')) t(x)"
        assert validate(db, sql)["allowed"], validate(db, sql)
        with db.cursor() as agent:
            enforce(agent)
            agent.execute(sql).fetchall()
        # A real selected replacement must still be refused alongside the trusted one.
        selected = sql.replace(f"{source}(x)", f"{source}(x COLLATE nocase)")
        assert validate(db, selected)["code"] == "forbidden", validate(db, selected)


@pytest.mark.parametrize("target", ["epoch", "julian", "year", "month", "day", "decade", "century",
                                    "millennium", "microsecond", "millisecond", "second", "minute", "hour",
                                    "dayofweek", "isodow", "week", "isoyear", "quarter", "dayofyear", "yearweek",
                                    "era", "timezone", "timezone_hour", "timezone_minute"])
def test_date_part_only_claims_selected_target(db, target):
    db.execute(f"CREATE VIEW trusted AS SELECT {target}(TIMESTAMP '2020-01-01') y")
    configure(db, {"blocked_functions": grants(target, schema_path=("main",))})
    # epoch selects only epoch on both engines. Pick julian when testing epoch itself.
    part = "julian" if target == "epoch" else "epoch"
    sql = f"SELECT date_part('{part}', TIMESTAMP '2020-01-01'), (SELECT y FROM trusted)"
    assert validate(db, sql)["allowed"], validate(db, sql)
    with db.cursor() as agent:
        enforce(agent)
        agent.execute(sql).fetchall()
    if ENGINE_MAJOR >= 2 or target in {"epoch", "julian"}:
        selected = sql.replace(f"'{part}'", f"'{target}'")
        assert validate(db, selected)["code"] == "forbidden", validate(db, selected)


@pytest.mark.parametrize("source,target", [("min", "arg_min"), ("max", "arg_max")])
def test_column_and_session_collation_still_select_replacement(db, source, target):
    db.execute("CREATE TABLE collated(x VARCHAR COLLATE nocase); INSERT INTO collated VALUES ('a')")
    configure(db, {"blocked_functions": grants(target, schema_path=("main",))})
    assert validate(db, f"SELECT {source}(x) FROM collated")["code"] == "forbidden"
    db.execute("SET default_collation='nocase'")
    assert validate(db, f"SELECT {source}(x) FROM (VALUES ('a')) t(x)")["code"] == "forbidden"


@pytest.mark.parametrize("source,target", [("min", "arg_min"), ("max", "arg_max")])
def test_prepared_siblings_recheck_the_actual_replacement(db, source, target):
    db.execute(f"CREATE VIEW trusted AS SELECT {target}(x,x) y FROM (VALUES ('a')) t(x)")
    configure(db, {"blocked_functions": grants(target, schema_path=("main",))})
    with db.cursor() as agent:
        enforce(agent)
        sql = f"SELECT {source}(x), (SELECT y FROM trusted) FROM (VALUES (?::VARCHAR)) t(x)"
        assert agent.execute(sql, ['a']).fetchone() == ('a', 'a')
        with pytest.raises(duckdb.PermissionException, match="Gatekeeper denied"):
            agent.execute(sql.replace(f"{source}(x)", f"{source}(x COLLATE nocase)"), ['a'])


def test_nested_and_window_occurrences_keep_substitution_blocks(db):
    configure(db, {"blocked_functions": grants("arg_min", "quantile_disc", schema_path=("main",))})
    for sql in ["SELECT min(x COLLATE nocase) OVER () FROM (VALUES ('a')) t(x)",
                "SELECT (SELECT min(x COLLATE nocase) FROM (VALUES ('a')) t(x))",
                "SELECT quantile(x, 0.5) FROM (VALUES (1)) t(x)",
                "SELECT quantile(x, 0.5) OVER () FROM (VALUES (1)) t(x)"]:
        assert validate(db, sql)["code"] == "forbidden", (sql, validate(db, sql))
