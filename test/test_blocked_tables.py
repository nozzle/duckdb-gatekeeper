"""Deny-wins object rules, including resolved dependencies and canonical settings."""
import itertools

import duckdb
import pytest

from test_gatekeeper import db
from test_wildcard_tables import rule
from typed_helpers import configure, validate


@pytest.mark.parametrize("catalog,schema,table", list(itertools.product(
    ["memory", "*", None], ["reporting", "*"], ["orders", "*"])))
def test_blocks_match_all_components_and_override_allows(db, catalog, schema, table):
    db.execute("CREATE SCHEMA reporting; CREATE TABLE reporting.orders(x INT)")
    block = rule(catalog, schema, table)
    for options in [{"blocked_tables": [block]},
                    {"allowed_tables": [rule("memory", "reporting", "orders")], "blocked_tables": [block]}]:
        result = validate(db, "SELECT * FROM reporting.orders", options)
        assert result["code"] == "forbidden", result
        assert result["violations"][0]["message"] == "object is blocked"
        assert result["objects"] == result["functions"] == []
    for field in ["catalog", "schema", "table"]:
        assert validate(db, "SELECT * FROM reporting.orders", {
            "blocked_tables": [{**block, field: "other"}]
        })["allowed"]


def test_blocks_in_either_layer_cannot_be_overridden(db):
    db.execute("CREATE TABLE t(x INT); CREATE TABLE u(x INT)")
    configure(db, {"allowed_tables": [rule()], "blocked_tables": [rule(table="t")]})
    for request in [{}, {"blocked_tables": []}, {"allowed_tables": [rule(table="t")]}]:
        assert not validate(db, "SELECT * FROM t", request)["allowed"]
    assert validate(db, "SELECT * FROM u")["allowed"]
    assert not validate(db, "SELECT * FROM u", {"blocked_tables": [rule(table="u")]})["allowed"]
    assert not validate(db, "SELECT * FROM u", {"allowed_tables": []})["allowed"]
    configure(db, {"blocked_tables": []})
    assert validate(db, "SELECT * FROM t")["allowed"]


@pytest.mark.parametrize("blocked", ["t", "v"])
def test_view_and_macro_dependencies_are_blocked(db, blocked):
    db.execute("CREATE TABLE t(x INT); CREATE VIEW v AS SELECT * FROM t; CREATE MACRO m() AS TABLE SELECT * FROM v")
    configure(db, {"allowed_functions": ["m"], "blocked_tables": [rule(table=blocked)]})
    for sql in ["SELECT * FROM v", "SELECT * FROM m()"]:
        result = validate(db, sql)
        assert result["code"] == "forbidden", result
        assert result["violations"][0]["table"] == blocked


def test_blocks_use_resolved_objects_not_cte_names_and_include_future_temp_tables(db):
    configure(db, {"blocked_tables": [{"schema": "main", "table": "t"}]})
    assert validate(db, "WITH t AS (SELECT 1 x) SELECT * FROM t")["allowed"]
    db.execute("CREATE TABLE t(x INT); CREATE TEMP TABLE t(x INT)")
    result = validate(db, "SELECT * FROM t")
    assert result["violations"][0]["catalog"] == "temp"
    configure(db, {"blocked_tables": [rule("memory", "main", "t")]})
    assert validate(db, "SELECT * FROM t")["allowed"]
    assert not validate(db, "SELECT * FROM memory.main.t")["allowed"]


def test_blocks_do_not_form_cross_products_or_partial_globs(db):
    db.execute("ATTACH ':memory:' AS lake; CREATE SCHEMA reporting; CREATE SCHEMA lake.reporting; "
               "CREATE TABLE main.t(x INT); CREATE TABLE reporting.t(x INT); "
               "CREATE TABLE lake.main.t(x INT); CREATE TABLE lake.reporting.t(x INT)")
    options = {"blocked_tables": [rule("memory", "main"), rule("lake", "reporting")]}
    for catalog, schema in itertools.product(["memory", "lake"], ["main", "reporting"]):
        assert validate(db, f"SELECT * FROM {catalog}.{schema}.t", options)["allowed"] == (
            (catalog, schema) not in [("memory", "main"), ("lake", "reporting")])
    db.execute('CREATE TABLE "sales_*"(x INT); CREATE TABLE sales_a(x INT)')
    options = {"blocked_tables": [rule(table="sales_*")]}
    assert not validate(db, 'SELECT * FROM "sales_*"', options)["allowed"]
    assert validate(db, "SELECT * FROM sales_a", options)["allowed"]


def test_internal_blocks_accept_wildcards_even_with_exact_permission(db):
    exact = rule("system", "main", "duckdb_tables")
    configure(db, {"allowed_tables": [exact]})
    result = validate(db, "SELECT * FROM duckdb_tables", {"allowed_tables": [exact], "blocked_tables": [rule()]})
    assert result["code"] == "forbidden"
    assert result["violations"][0]["rule"] == "table"
    assert result["violations"][0]["message"] == "object is blocked"


@pytest.mark.parametrize("sql", ["SHOW TABLES", "SHOW ALL TABLES", "SHOW TABLES FROM main"])
def test_nonempty_blocks_disable_schema_wide_show(db, sql):
    result = validate(db, sql, {"blocked_tables": [rule(table="secret")]})
    assert result["code"] == "forbidden"
    assert any(v["rule"] == "table" for v in result["violations"])


@pytest.mark.parametrize("statement", ["DESCRIBE", "SHOW"])
def test_table_description_checks_resolved_blocks(db, statement):
    db.execute("CREATE TABLE secret(x INT); CREATE TABLE other(x INT)")
    options = {"blocked_tables": [rule("memory", "main", "secret")]}
    result = validate(db, f"{statement} secret", options)
    assert result["code"] == "forbidden", result
    violation = result["violations"][0]
    assert violation["message"] == "object is blocked"
    assert (violation["catalog"], violation["schema"], violation["table"]) == ("memory", "main", "secret")
    assert validate(db, f"{statement} other", options)["allowed"]


def test_blocks_round_trip_without_enabling_allowlist(db):
    entries = [{"schema": "MAIN", "table": "T"}, {"catalog": None, "schema": "MAIN", "table": "T"}]
    configure(db, {"blocked_tables": entries})
    db.execute("SET gatekeeper_policy = current_setting('gatekeeper_policy')")
    policy = db.execute("SELECT current_setting('gatekeeper_policy')").fetchone()[0]
    assert policy["blocked_tables"] == [rule("", "main", "t")]
    assert not policy["restrict_tables"]
    db.execute("CREATE TABLE t(x INT); CREATE TABLE u(x INT)")
    assert not validate(db, "SELECT * FROM t")["allowed"]
    assert validate(db, "SELECT * FROM u")["allowed"]
    db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), blocked_tables := [])")
    assert validate(db, "SELECT * FROM t")["allowed"]


@pytest.mark.parametrize("entries", [None, [None], [{"table": "t"}], [{"schema": None, "table": "t"}],
                                      [{"schema": "main", "table": ""}],
                                      [{"schema": "main", "table": "t", "catlog": "memory"}]])
def test_invalid_blocks_fail_closed_and_preserve_configuration(db, entries):
    configure(db, {"blocked_tables": [rule(table="t")]})
    before = db.execute("SELECT current_setting('gatekeeper_policy')").fetchone()[0]
    result = validate(db, "SELECT 1", {"blocked_tables": entries})
    assert result["code"] == "invalid_input"
    with pytest.raises(duckdb.Error):
        configure(db, {"blocked_tables": entries})
    assert db.execute("SELECT current_setting('gatekeeper_policy')").fetchone()[0] == before


@pytest.mark.parametrize("entry", ["{catlog:'memory', schema:'main', 'table':'t'}",
                                  "{catalog:NULL, schema:'main', 'table':'t'}",
                                  "{catalog:'memory', schema:NULL, 'table':'t'}"])
def test_canonical_blocks_reject_null_or_misspelled_fields(db, entry):
    with pytest.raises(duckdb.Error, match="NULL policy field"):
        db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), blocked_tables := ["
                   + entry + "])")


def test_row_varying_block_structs(db):
    db.execute("CREATE TABLE t(x INT)")
    rows = db.execute("""SELECT gatekeeper_validate('SELECT * FROM t', blocked_tables :=
        CASE WHEN i=0 THEN [] ELSE [{schema:'main', 'table':'t'}] END).allowed
        FROM range(2) r(i) ORDER BY i""").fetchall()
    assert rows == [(True,), (False,)]
