"""Resolved wildcard matching, independent policy layers, and migration boundaries."""
import itertools

import duckdb
import pytest

from test_gatekeeper import db
from typed_helpers import configure, validate


def rule(catalog="*", schema="*", table="*"):
    return {"catalog": catalog, "schema": schema, "table": table}


@pytest.mark.parametrize("catalog,schema,table", list(itertools.product(["memory", "*"], ["reporting", "*"], ["orders", "*"])))
def test_every_wildcard_combination(db, catalog, schema, table):
    db.execute("CREATE SCHEMA reporting; CREATE TABLE reporting.orders(x INT)")
    options = {"allowed_tables": [rule(catalog, schema, table)]}
    result = validate(db, "SELECT * FROM reporting.orders", options)
    assert result["allowed"], result
    assert result["objects"] == [{"catalog": "memory", "schema": "reporting", "table": "orders", "type": "table"}]
    for field in ["catalog", "schema", "table"]:
        denied = {"allowed_tables": [{**options["allowed_tables"][0], field: "other"}]}
        assert not validate(db, "SELECT * FROM reporting.orders", denied)["allowed"]


def test_rules_do_not_form_a_cross_product(db):
    db.execute("ATTACH ':memory:' AS lake; CREATE SCHEMA reporting; CREATE SCHEMA lake.reporting; "
               "CREATE TABLE main.t(x INT); CREATE TABLE reporting.t(x INT); "
               "CREATE TABLE lake.main.t(x INT); CREATE TABLE lake.reporting.t(x INT)")
    options = {"allowed_tables": [rule("memory", "main"), rule("lake", "reporting")]}
    for catalog, schema in itertools.product(["memory", "lake"], ["main", "reporting"]):
        assert validate(db, f"SELECT * FROM {catalog}.{schema}.t", options)["allowed"] == (
            (catalog, schema) in [("memory", "main"), ("lake", "reporting")])


def test_wildcard_layers_intersect_at_the_resolved_object(db):
    db.execute("ATTACH ':memory:' AS lake; CREATE SCHEMA reporting; CREATE SCHEMA lake.reporting; "
               "CREATE TABLE main.orders(x INT); CREATE TABLE reporting.orders(x INT); "
               "CREATE TABLE lake.reporting.orders(x INT)")
    configure(db, {"allowed_tables": [rule("memory")]})
    request = {"allowed_tables": [rule(schema="reporting")]}
    assert validate(db, "SELECT * FROM memory.reporting.orders", request)["allowed"]
    assert not validate(db, "SELECT * FROM memory.main.orders", request)["allowed"]
    assert not validate(db, "SELECT * FROM lake.reporting.orders", request)["allowed"]
    assert not validate(db, "SELECT * FROM lake.reporting.orders", {"allowed_tables": [rule()]})["allowed"]
    assert not validate(db, "SELECT * FROM memory.reporting.orders", {"allowed_tables": []})["allowed"]


def test_wildcards_round_trip_and_cover_future_objects(db):
    configure(db, {"allowed_tables": [rule("MeMoRy", "RePoRtInG"), rule("MeMoRy", "RePoRtInG")]})
    db.execute("SET gatekeeper_policy = current_setting('gatekeeper_policy')")
    policy = db.execute("SELECT current_setting('gatekeeper_policy')").fetchone()[0]
    assert policy["allowed_tables"] == [rule("memory", "reporting")]
    assert policy["restrict_tables"]
    db.execute("CREATE SCHEMA reporting; CREATE TABLE reporting.future(x INT)")
    assert validate(db, "SELECT * FROM reporting.future")["allowed"]
    db.execute("CREATE TABLE main.future(x INT); SET schema='main'")
    assert not validate(db, "SELECT * FROM future")["allowed"]
    db.execute("SET schema='reporting'")
    assert validate(db, "SELECT * FROM future")["allowed"]
    db.execute("CREATE TEMP TABLE future(x INT)")
    assert not validate(db, "SELECT * FROM future")["allowed"]
    configure(db, {"allowed_tables": [rule(schema="main", table="future")]})
    assert validate(db, "SELECT * FROM future")["objects"][0]["catalog"] == "temp"


@pytest.mark.parametrize("name", ["sales_*", "sales_?", "sales_%", "sales_[ab]"])
def test_only_whole_component_star_is_special(db, name):
    db.execute(f'CREATE TABLE "{name}"(x INT); CREATE TABLE sales_a(x INT)')
    options = {"allowed_tables": [rule(table=name)]}
    assert validate(db, f'SELECT * FROM "{name}"', options)["allowed"]
    assert not validate(db, "SELECT * FROM sales_a", options)["allowed"]


@pytest.mark.parametrize("entry", [rule(), rule(schema="main"), rule(table="duckdb_tables"),
                                   rule("system", "*", "duckdb_tables"), rule("system", "main")])
def test_internal_objects_need_exact_schema_and_table_in_each_layer(db, entry):
    exact = rule("system", "main", "duckdb_tables")
    for ceiling, request in [(entry, exact), (exact, entry)]:
        configure(db, {"allowed_tables": [ceiling]})
        result = validate(db, "SELECT * FROM duckdb_tables", {"allowed_tables": [request]})
        assert not result["allowed"]
        assert "internal_object" in {v["rule"] for v in result["violations"]}, result


@pytest.mark.parametrize("catalog", ["*", None, "system"])
def test_exact_internal_permission_still_cannot_admit_metadata_readers(db, catalog):
    options = {"allowed_tables": [rule(catalog, "main", "duckdb_tables")]}
    configure(db, options)
    result = validate(db, "SELECT * FROM duckdb_tables", options)
    assert not result["allowed"]
    assert "internal_object" not in {v["rule"] for v in result["violations"]}
    assert any(v["function_name"] == "duckdb_tables" for v in result["violations"])


@pytest.mark.parametrize("sql", ["SHOW TABLES", "SHOW ALL TABLES", "SHOW TABLES FROM main"])
def test_show_is_not_authorized_by_a_broad_wildcard(db, sql):
    result = validate(db, sql, {"allowed_tables": [rule()]})
    assert result["code"] == "forbidden"
    assert "table" in {v["rule"] for v in result["violations"]}


@pytest.mark.parametrize("name", ["allowed_catalogs", "allowed_schemas"])
def test_retired_options_are_rejected_by_both_apis(db, name):
    configure(db, {"allowed_tables": []})
    before = db.execute("SELECT current_setting('gatekeeper_policy')").fetchone()[0]
    for sql in [f"CALL gatekeeper_configure({name} := ['memory'])",
                f"SELECT gatekeeper_validate('SELECT 1', {name} := ['memory'])"]:
        with pytest.raises(duckdb.Error, match="unknown option|Invalid named parameter"):
            db.execute(sql)
    assert db.execute("SELECT current_setting('gatekeeper_policy')").fetchone()[0] == before


def test_table_wildcards_do_not_grant_functions_or_types(db):
    db.execute("CREATE MACRO custom(x) AS abs(x); CREATE TYPE customer AS ENUM ('a')")
    broad = {"allowed_tables": [rule()]}
    assert not validate(db, "SELECT custom(1)", broad)["allowed"]
    assert not validate(db, "SELECT NULL::customer", broad)["allowed"]
    configure(db, {"allowed_tables": [], "allowed_functions": ["custom"],
                   "allowed_types": [{"catalog": "memory", "schema": "main", "type": "customer"}]})
    assert validate(db, "SELECT memory.main.custom(1), NULL::memory.main.customer")["allowed"]
    assert not validate(db, "SELECT custom(1)", {"blocked_functions": ["custom"]})["allowed"]
    # Type identities and function names have not acquired wildcard semantics.
    assert not validate(db, "SELECT NULL::customer", {
        "allowed_types": [{"catalog": "*", "schema": "main", "type": "customer"}]})["allowed"]
    assert not validate(db, "SELECT custom(1)", {"use_default_functions": False, "allowed_functions": ["*"]})["allowed"]
