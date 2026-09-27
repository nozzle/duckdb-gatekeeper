"""Deny-wins object rules, including resolved dependencies and canonical settings."""
import itertools

import duckdb
import pytest

from support.artifact import ENGINE_MAJOR
from support.typed_helpers import configure, policy, rule, validate


@pytest.mark.parametrize("catalog,schema,table", list(itertools.product(
    ["memory", "*", None], ["reporting", "*"], ["orders", "*"])))
def test_blocks_match_all_components_and_override_allows(db, catalog, schema, table):
    db.execute("CREATE SCHEMA reporting; CREATE TABLE reporting.orders(x INT)")
    block = rule(catalog, [schema], table)
    for options in [{"blocked_tables": [block]},
                    {"allowed_tables": [rule("memory", ["reporting"], "orders")], "blocked_tables": [block]}]:
        result = validate(db, "SELECT * FROM reporting.orders", options)
        assert result["code"] == "forbidden", result
        assert result["violations"][0]["message"] == "object is blocked"
        assert result["objects"] == result["functions"] == []
    for field in ["catalog", "schema_path", "table"]:
        assert validate(db, "SELECT * FROM reporting.orders", {
            "blocked_tables": [{**block, field: ["other"] if field == "schema_path" else "other"}]
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


def test_blocks_do_not_reach_into_trusted_definitions(db):
    # A block applies to the objects the caller names. What a trusted view or table macro reads is its own: a
    # block on the table behind v reaches neither v nor the macro over v, and a block on v reaches the caller's
    # v but not the macro whose body reads it. Every object read is still evidence.
    db.execute("CREATE TABLE t(x INT); CREATE VIEW v AS SELECT * FROM t; CREATE MACRO m() AS TABLE SELECT * FROM v")
    configure(db, {"allowed_functions": [{"schema_path": ["*"], "name": "m"}], "blocked_tables": [rule(table="t")]})
    for sql in ["SELECT * FROM v", "SELECT * FROM m()"]:
        result = validate(db, sql)
        assert result["allowed"] and {o["table"] for o in result["objects"]} >= {"t", "v"}, (sql, result)
    denied = validate(db, "SELECT * FROM v, t")
    assert denied["code"] == "forbidden" and denied["violations"][0]["table"] == "t", denied
    configure(db, {"allowed_functions": [{"schema_path": ["*"], "name": "m"}], "blocked_tables": [rule(table="v")]})
    denied = validate(db, "SELECT * FROM v")
    assert denied["code"] == "forbidden" and denied["violations"][0]["table"] == "v", denied
    assert validate(db, "SELECT * FROM m()")["allowed"]
    assert validate(db, "SELECT * FROM m(), t")["allowed"]
    assert validate(db, "SELECT * FROM m(), v")["code"] == "forbidden"


def test_blocks_use_resolved_objects_not_cte_names_and_include_future_temp_tables(db):
    configure(db, {"blocked_tables": [{"schema_path": ["main"], "table": "t"}]})
    assert validate(db, "WITH t AS (SELECT 1 x) SELECT * FROM t")["allowed"]
    db.execute("CREATE TABLE t(x INT); CREATE TEMP TABLE t(x INT)")
    result = validate(db, "SELECT * FROM t")
    assert result["violations"][0]["catalog"] == "temp"
    configure(db, {"blocked_tables": [rule("memory", ["main"], "t")]})
    assert validate(db, "SELECT * FROM t")["allowed"]
    assert not validate(db, "SELECT * FROM memory.main.t")["allowed"]


def test_blocks_do_not_form_cross_products_or_partial_globs(db):
    db.execute("ATTACH ':memory:' AS lake; CREATE SCHEMA reporting; CREATE SCHEMA lake.reporting; "
               "CREATE TABLE main.t(x INT); CREATE TABLE reporting.t(x INT); "
               "CREATE TABLE lake.main.t(x INT); CREATE TABLE lake.reporting.t(x INT)")
    options = {"blocked_tables": [rule("memory", ["main"]), rule("lake", ["reporting"])]}
    for catalog, schema in itertools.product(["memory", "lake"], ["main", "reporting"]):
        assert validate(db, f"SELECT * FROM {catalog}.{schema}.t", options)["allowed"] == (
            (catalog, schema) not in [("memory", "main"), ("lake", "reporting")])
    db.execute('CREATE TABLE "sales_*"(x INT); CREATE TABLE sales_a(x INT)')
    options = {"blocked_tables": [rule(table="sales_*")]}
    assert not validate(db, 'SELECT * FROM "sales_*"', options)["allowed"]
    assert validate(db, "SELECT * FROM sales_a", options)["allowed"]


def test_internal_blocks_accept_wildcards_even_with_exact_permission(db):
    exact = rule("system", ["main"], "duckdb_tables")
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
    options = {"blocked_tables": [rule("memory", ["main"], "secret")]}
    result = validate(db, f"{statement} secret", options)
    if statement == "SHOW" and ENGINE_MAJOR >= 2:
        # DuckDB 2.0's `SHOW name` may read a setting's value at bind time when no such table exists, with no
        # function for the never-bind list to see, so the grammar refuses that kind whatever the name resolves
        # to; DESCRIBE name is the supported spelling.
        assert result["code"] == "unsupported" and result["violations"][0]["message"] == "unsupported SHOW kind"
        assert not validate(db, f"{statement} other", options)["allowed"]
        return
    assert result["code"] == "forbidden", result
    violation = result["violations"][0]
    assert violation["message"] == "object is blocked"
    assert (violation["catalog"], violation["schema_path"], violation["table"]) == ("memory", ["main"], "secret")
    assert validate(db, f"{statement} other", options)["allowed"]


def test_blocks_round_trip_without_enabling_allowlist(db):
    entries = [{"schema_path": ["MAIN"], "table": "T"}, {"catalog": None, "schema_path": ["MAIN"], "table": "T"}]
    configure(db, {"blocked_tables": entries})
    db.execute("SET gatekeeper_policy = current_setting('gatekeeper_policy')")
    canonical = policy(db)
    assert canonical["blocked_tables"] == [rule("", ["main"], "t")]
    assert not canonical["restrict_tables"]
    db.execute("CREATE TABLE t(x INT); CREATE TABLE u(x INT)")
    assert not validate(db, "SELECT * FROM t")["allowed"]
    assert validate(db, "SELECT * FROM u")["allowed"]
    db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), blocked_tables := [])")
    assert validate(db, "SELECT * FROM t")["allowed"]


@pytest.mark.parametrize("entries", [None, [None], [{"table": "t"}], [{"schema_path": None, "table": "t"}],
                                      [{"schema_path": ["main"], "table": ""}],
                                      [{"schema_path": ["main"], "table": "t", "catlog": "memory"}]])
def test_invalid_blocks_fail_closed_and_preserve_configuration(db, entries):
    configure(db, {"blocked_tables": [rule(table="t")]})
    before = policy(db)
    result = validate(db, "SELECT 1", {"blocked_tables": entries})
    assert result["code"] == "invalid_input"
    with pytest.raises(duckdb.Error):
        configure(db, {"blocked_tables": entries})
    assert policy(db) == before


@pytest.mark.parametrize("entry", ["{catlog:'memory', schema_path:['main'], 'table':'t'}",
                                  "{catalog:NULL, schema_path:['main'], 'table':'t'}",
                                  "{catalog:'memory', schema_path:NULL, 'table':'t'}"])
def test_canonical_blocks_reject_null_or_misspelled_fields(db, entry):
    with pytest.raises(duckdb.Error, match="NULL policy field"):
        db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), blocked_tables := ["
                   + entry + "])")


def test_prepared_block_structs(db):
    db.execute("CREATE TABLE t(x INT)")
    for blocks, allowed in [([], True), ([{"schema_path": ["main"], "table": "t"}], False), ([], True)]:
        assert db.execute("SELECT allowed FROM gatekeeper_validate('SELECT * FROM t', blocked_tables := ?)",
                          [blocks]).fetchall() == [(allowed,)]
