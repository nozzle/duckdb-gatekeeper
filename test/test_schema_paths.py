"""Path identity, strict policy inputs, and nested-schema authorization."""
import json

import duckdb
import pytest

from support.artifact import ENGINE_MAJOR
from support.audit import decisions, enable
from support.enforcement import enforce, settle
from support.typed_helpers import configure, policy, validate


def table(path, name="orders", catalog="memory"):
    return {"catalog": catalog, "schema_path": path, "table": name}


@pytest.mark.parametrize("path", [None, "main", [], [None], [1], [""], ["a\0b"], ["main", None]])
@pytest.mark.parametrize("option", ["allowed_tables", "blocked_tables"])
def test_invalid_paths_fail_closed_in_both_input_encodings(db, path, option):
    configure(db, {"blocked_functions": ["md5"]})
    before = policy(db)
    options = {option: [table(path)]}
    for arguments in [options, {"json": json.dumps({"version": 2, "options": options})}]:
        assert validate(db, "SELECT 1", arguments)["code"] == "invalid_input"
        with pytest.raises(duckdb.BinderException):
            configure(db, arguments)
        assert policy(db) == before


def test_old_schema_field_and_json_version_are_rejected(db):
    for options in [{"allowed_tables": [{"schema": "main", "table": "orders"}]},
                    {"allowed_tables": [{**table(["main"]), "schema": "main"}]},
                    {"json": '{"version":1,"options":{}}'}]:
        assert validate(db, "SELECT 1", options)["code"] == "invalid_input"
        with pytest.raises(duckdb.BinderException):
            configure(db, options)


def test_paths_preserve_order_duplicates_and_literal_dots_on_both_engines(db):
    db.execute('CREATE SCHEMA "finance.reports"; CREATE TABLE "finance.reports".orders(i INT)')
    sql = 'SELECT * FROM "finance.reports".orders'
    exact = table(["finance.reports"])
    result = validate(db, sql, {"allowed_tables": [exact]})
    assert result["allowed"] and result["caller_objects"] == [{**exact, "type": "table"}]
    assert not validate(db, sql, {"allowed_tables": [table(["finance", "reports"])]})["allowed"]
    entries = [table(["B", "A"]), table(["A", "B"]), table(["A", "A"])]
    configure(db, {"allowed_tables": entries})
    assert policy(db)["allowed_tables"] == [table(["a", "a"]), table(["a", "b"]), table(["b", "a"])]
    db.execute("SET gatekeeper_policy = current_setting('gatekeeper_policy')")
    assert policy(db)["allowed_tables"] == [table(["a", "a"]), table(["a", "b"]), table(["b", "a"])]


@pytest.mark.parametrize("path", ["NULL", "[]", "['main', NULL]", "['']"])
def test_canonical_setting_rejects_invalid_paths_atomically(db, path):
    configure(db, {"allowed_tables": [table(["main"])]})
    before = policy(db)
    with pytest.raises(duckdb.Error):
        db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), "
                   f"allowed_tables := [{{catalog: 'memory', schema_path: {path}, 'table': 'orders'}}])")
    assert policy(db) == before


@pytest.fixture
def nested(db):
    if ENGINE_MAJOR < 2:
        pytest.skip("Nested schemas require DuckDB 2.0")
    db.execute("CREATE SCHEMA finance; CREATE SCHEMA finance.reports; "
               "CREATE SCHEMA sales; CREATE SCHEMA sales.reports; "
               "CREATE SCHEMA finance.reports.monthly; "
               "CREATE TABLE finance.reports.orders AS SELECT 1 AS i; "
               "CREATE TABLE sales.reports.orders AS SELECT 2 AS i; "
               "CREATE TABLE finance.reports.monthly.orders AS SELECT 3 AS i; "
               "CREATE VIEW main.visible AS SELECT * FROM sales.reports.orders; "
               "CREATE MACRO main.hidden() AS (SELECT sum(i) FROM sales.reports.orders)")
    return db


@pytest.mark.parametrize("reference", ["finance.reports.orders", "memory.finance.reports.orders"])
def test_nested_identity_and_exact_depth_wildcards(nested, reference):
    sql = f"SELECT * FROM {reference}"
    exact = table(["finance", "reports"])
    result = validate(nested, sql, {"allowed_tables": [exact]})
    assert result["allowed"] and result["objects"] == result["caller_objects"] == [{**exact, "type": "table"}]
    for path, allowed in [(["finance", "reports"], True), (["finance", "*"], True), (["*", "reports"], True),
                          (["*", "*"], True), (["*"], False), (["reports"], False), (["sales", "reports"], False),
                          (["finance.reports"], False), (["finance", "*", "*"], False)]:
        assert validate(nested, sql, {"allowed_tables": [table(path)]})["allowed"] is allowed
        blocked = validate(nested, sql, {"blocked_tables": [table(path)]})
        assert blocked["allowed"] is not allowed
        if allowed:
            assert blocked["violations"][0]["schema_path"] == ["finance", "reports"]
    assert not validate(nested, "SELECT * FROM finance.reports.monthly.orders",
                        {"allowed_tables": [table(["finance", "*"])]})["allowed"]


def test_parent_paths_prevent_identity_collisions_and_preserve_trusted_attribution(nested):
    exact = table(["finance", "reports"])
    options = {"allowed_tables": [exact, table(["main"], "visible")]}
    result = validate(nested, "SELECT * FROM finance.reports.orders, visible", options)
    assert result["allowed"], result
    assert result["caller_objects"] == [{**exact, "type": "table"}, {**table(["main"], "visible"), "type": "view"}]
    assert {**table(["sales", "reports"]), "type": "table"} in result["objects"]
    for reference in ["sales.reports.orders", "memory.sales.reports.orders"]:
        assert not validate(nested, f"SELECT * FROM visible, {reference}", options)["allowed"]
    configure(nested, {"allowed_functions": [{"schema_path": ["main"], "name": "hidden"}]})
    assert validate(nested, "SELECT hidden() FROM finance.reports.orders", options)["allowed"]
    assert not validate(nested, "SELECT hidden() FROM sales.reports.orders", options)["allowed"]


def test_nested_enforcement_and_audit(nested):
    exact = table(["finance", "reports"])
    configure(nested, {"allowed_tables": [exact]})
    enable(nested, "debug")
    with nested.cursor() as agent:
        enforce(agent)
        assert agent.execute("SELECT * FROM finance.reports.orders").fetchall() == [(1,)]
        assert agent.execute("SELECT * FROM memory.finance.reports.orders WHERE i = ?", [1]).fetchall() == [(1,)]
        for sql in ["SELECT * FROM sales.reports.orders", "SELECT * FROM finance.reports.monthly.orders"]:
            with pytest.raises(duckdb.PermissionException):
                agent.execute(sql)
            settle(agent)
        found = decisions(nested, "mode = 'enforce'")
        assert any(r["allowed"] and r["caller_objects"] == [{**exact, "type": "table"}] for r in found)
        assert any(not r["allowed"] and r["violations"][0]["schema_path"] == ["sales", "reports"] for r in found)


def test_nested_function_identity_and_literal_constructor_qualification(nested):
    nested.execute("CREATE MACRO finance.reports.calc(x) AS abs(x); "
                   "CREATE MACRO finance.reports.list_value(x) AS [x]")
    configure(nested, {"allowed_functions": [{"schema_path": ["finance", "reports"], "name": "calc"}]})
    result = validate(nested, "SELECT finance.reports.calc(-1)")
    assert result["allowed"], result
    assert {"catalog": "memory", "schema_path": ["finance", "reports"], "name": "calc", "type": "macro"} in result["functions"]
    result = validate(nested, "SELECT quantile_cont(i, finance.reports.list_value(0.5)) FROM finance.reports.orders")
    assert result["code"] == "forbidden", result


def test_nested_catalog_ambiguity_and_literal_dot_are_distinct(nested):
    nested.execute('CREATE SCHEMA "finance.reports"; CREATE TABLE "finance.reports".orders AS SELECT 4 AS i; '
                   "ATTACH ':memory:' AS finance; CREATE SCHEMA finance.reports; "
                   "CREATE TABLE finance.reports.orders AS SELECT 5 AS i")
    # The attached catalog takes precedence for the first component of a multi-part name.
    for reference, entry in [("finance.reports.orders", table(["reports"], catalog="finance")),
                             ("memory.finance.reports.orders", table(["finance", "reports"])),
                             ('memory."finance.reports".orders', table(["finance.reports"]))]:
        result = validate(nested, f"SELECT * FROM {reference}", {"allowed_tables": [entry]})
        assert result["allowed"] and result["caller_objects"] == [{**entry, "type": "table"}]
    assert not validate(nested, "SELECT * FROM finance.reports.orders",
                        {"allowed_tables": [table(["finance", "reports"])]})["allowed"]


def test_nested_layers_intersect_and_blocks_win(nested):
    configure(nested, {"allowed_tables": [table(["finance", "*"])]})
    sql = "SELECT * FROM finance.reports.orders"
    assert validate(nested, sql, {"allowed_tables": [table(["*", "reports"])]})["allowed"]
    assert not validate(nested, "SELECT * FROM sales.reports.orders",
                        {"allowed_tables": [table(["*", "reports"])]})["allowed"]
    assert not validate(nested, sql, {"blocked_tables": [table(["*", "reports"])]})["allowed"]
    configure(nested, {"blocked_tables": [table(["finance", "*"])]})
    assert not validate(nested, sql, {"blocked_tables": [], "allowed_tables": [table(["*", "*"])]})["allowed"]


def test_nested_view_and_macro_bodies_keep_full_written_paths(nested):
    nested.execute("CREATE VIEW finance.reports.exposed AS SELECT * FROM sales.reports.orders; "
                   "CREATE MACRO finance.reports.hidden() AS (SELECT sum(i) FROM sales.reports.orders)")
    configure(nested, {"allowed_functions": [{"schema_path": ["finance", "reports"], "name": "hidden"}]})
    options = {"allowed_tables": [table(["finance", "reports"], "exposed")]}
    result = validate(nested, "SELECT * FROM finance.reports.exposed", options)
    assert result["allowed"] and result["caller_objects"] == [{**options["allowed_tables"][0], "type": "view"}]
    result = validate(nested, "SELECT finance.reports.hidden()", {"allowed_tables": []})
    assert result["allowed"] and result["caller_objects"] == []
    assert not validate(nested, "SELECT finance.reports.hidden() FROM sales.reports.orders",
                        {"allowed_tables": []})["allowed"]
