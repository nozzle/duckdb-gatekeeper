import json
import shutil

import pytest

from audit_inventory import compare, coverage
from inventory import load
from support.artifact import ROOT
from support.headers import never_bind_names
from support.typed_helpers import validate
from versions import BASELINE_FILENAME


def test_never_bind_inventory_excluded_from_defaults():
    names = never_bind_names()
    _, defaults = load()
    assert names and not set(names) & set(defaults)


def test_complete_default_inventory(db):
    db.execute("SET autoinstall_known_extensions=false; SET autoload_known_extensions=false")
    entries, names = load()
    assert len(entries) == 30
    assert len(names) == 953
    for name in names:
        quoted = '"' + name.replace('"', '""') + '"'
        sql = f"SELECT {quoted}(1)"
        result = validate(db, sql)
        if result["code"] == "parser":
            # A parser that owns a keyword-named call's syntax (the PEG parser rewrites even a quoted
            # position(..) into its operator) checks the arity before the binder ever sees the name; the
            # two-argument spelling reaches the binder under either parser.
            sql = f"SELECT {quoted}(1, 1)"
            result = validate(db, sql)
        assert result["code"] in {"ok", "binding"}, (name, result)
        assert not validate(db, sql, {"blocked_functions": [name]})["allowed"]


def test_nondefault_inventory(db):
    entries, defaults = load()
    for entry in entries.values():
        for name in entry["elevated"] + entry.get("unreviewed", []):
            assert name not in defaults
            sql = 'SELECT "' + name.replace('"', '""') + '"(1)'
            assert not validate(db, sql)["allowed"], name


def test_core_baseline_fully_reviewed():
    """Every 1.5.5 baseline name is classified; names an audit surfaces land in unreviewed."""
    entries, _ = load()
    baseline = json.loads((ROOT / "inventories/baselines" / BASELINE_FILENAME).read_text())
    assert coverage(baseline, entries)["unclassified_runtime_names"] == []
    assert entries["core"]["unreviewed"] == []
    assert entries["core"]["unreviewed_reason"]


def test_registered_aliases_share_classification(db):
    """apply/list_transform and friends are one implementation; the policy must not split them."""
    entries, _ = load()
    bucket = {}
    for entry in entries.values():
        for group in ["compute", "elevated", "unreviewed"]:
            for name in entry.get(group, []):
                bucket.setdefault(name, set()).add(group)
    pairs = db.execute("""SELECT DISTINCT lower(function_name), lower(alias_of) FROM duckdb_functions()
                          WHERE alias_of IS NOT NULL""").fetchall()
    assert len(pairs) > 50
    # New aliases stay excluded until classified; they do not block engine compatibility.
    mismatched = [(alias, canonical) for alias, canonical in pairs
                  if alias in bucket and bucket[alias] != bucket.get(canonical)]
    assert not mismatched, mismatched
    assert {"apply", "filter", "reduce"} <= set(bucket) and all(bucket[n] == {"compute"} for n in ["apply", "filter", "reduce"])


@pytest.mark.parametrize("sql, name", [
    ("SELECT current_date", "current_date"), ("SELECT today()", "today"), ("SELECT now()::VARCHAR", "now"),
    ("SELECT current_timestamp::VARCHAR", "get_current_timestamp"), ("SELECT localtime", "current_localtime"),
    ("SELECT age(TIMESTAMP '2000-01-01')", "age"), ("SELECT ago(INTERVAL 1 DAY)::VARCHAR", "ago"),
    ("SELECT random()", "random"), ("SELECT uuid()", "uuid"), ("SELECT uuidv7()", "uuidv7"),
    ("SELECT setseed(0.5)", "setseed"), ("SELECT current_user", "current_user"),
    ("SELECT has_table_privilege('t', 'SELECT')", "has_table_privilege"), ("SELECT pg_typeof(1)", "pg_typeof"),
    ("SELECT apply([1, 2], x -> x + 1)", "apply"), ("SELECT filter([1, 2], x -> x > 1)", "filter"),
    ("SELECT version()", "version"), ("SELECT reduce([1, 2], (a, b) -> a + b)", "reduce"),
    ("SELECT variant_typeof(1::VARIANT)", "variant_typeof"), ("SELECT st_astext(NULL::GEOMETRY)", "st_astext"),
    ("SELECT st_crs(st_geomfromwkb(NULL::BLOB))", "st_crs"),
    ("FROM duckdb_keywords()", "duckdb_keywords"), ("FROM pg_timezone_names()", "pg_timezone_names"),
])
def test_clock_random_and_compatibility_names_are_defaults(db, sql, name):
    """Each default is blockable and disappears with use_default_functions=false."""
    db.execute("CREATE TABLE t AS SELECT 1 x")
    db.execute(sql).fetchall()
    assert validate(db, sql)["allowed"], (name, validate(db, sql))
    for options in [{"blocked_functions": [name]}, {"use_default_functions": False}]:
        result = validate(db, sql, options)
        assert result["code"] == "forbidden", (name, options, result)
        assert any(v["rule"] == "function" and v["function_name"] == name for v in result["violations"]), result


@pytest.mark.parametrize("sql, name", [
    ("SELECT current_query()", "current_query"), ("SELECT txid_current()", "txid_current"),
    ("SELECT current_setting('threads')", "current_setting"), ("SELECT getvariable('x')", "getvariable"),
    ("SELECT stats(1)", "stats"), ("SELECT make_type('INTEGER')", "make_type"),
    ("SELECT st_setcrs(NULL::GEOMETRY, 'EPSG:4326')", "st_setcrs"), ("SELECT switch(1, MAP {1: 'a'}, 'b')", "switch"),
    ("SELECT pg_sleep(0)", "pg_sleep"), ("SELECT sleep_ms(0)", "sleep_ms"),
    ("SELECT finalize(count(*) EXPORT_STATE) FROM t", "finalize"),
    ("SELECT finalize(combine(count(*) EXPORT_STATE, count(*) EXPORT_STATE)) FROM t", "combine"),
    ("FROM pragma_platform()", "pragma_platform"), ("FROM duckdb_coordinate_systems()", "duckdb_coordinate_systems"),
    ("SELECT parse_duckdb_log_message('FileSystem', '')", "parse_duckdb_log_message"),
    ("SELECT __internal_decompress_string(1::UBIGINT)", "__internal_decompress_string"),
    ("SELECT vector_type(1)", "vector_type"), ("FROM test_all_types()", "test_all_types"),
])
def test_inspection_and_internal_names_are_excluded(db, sql, name):
    """Reviewed and excluded from defaults; the reason for each is recorded in core.json notes."""
    db.execute("CREATE TABLE t AS SELECT 1 x")
    result = validate(db, sql)
    assert result["code"] == "forbidden" and result["error_message"] == "", (name, result)
    assert any(v["rule"] == "function" and v["function_name"] == name for v in result["violations"]), result


def test_audit_deltas():
    baseline = json.loads((ROOT / "inventories/baselines" / BASELINE_FILENAME).read_text())
    candidate = json.loads(json.dumps(baseline))
    assert not any(compare(baseline, candidate).values())
    candidate["functions"].append({"name": "unreviewed_function", "parameters": []})
    candidate["functions"][0]["returns"] = "CHANGED"
    candidate["duckdb_version"] = "v1.6.0"
    delta = compare(baseline, candidate)
    assert delta["added"] == ["unreviewed_function"]
    assert delta["changed"] and delta["version_changed"]
    entries, _ = load()
    assert coverage(candidate, entries)["unclassified_runtime_names"] == ["unreviewed_function"]


def test_inventory_conflicts(tmp_path):
    shutil.copytree(ROOT / "inventories", tmp_path / "inventories")
    path = tmp_path / "inventories/extensions/json.json"
    entry = json.loads(path.read_text())
    entry["elevated"] = sorted(entry["elevated"] + ["sum"])
    path.write_text(json.dumps(entry))
    with pytest.raises(ValueError, match="cross-inventory"):
        load(tmp_path)


def test_audit_named_arguments_and_positional_order():
    baseline = {"duckdb_version": "v1.5.5", "loaded_extensions": [], "functions": [
        {"name": "reader", "kind": "table", "parameters": ["VARCHAR", "INTEGER"],
         "named_parameters": {"mode": "VARCHAR", "strict": "BOOLEAN"}}
    ]}
    candidate = json.loads(json.dumps(baseline))
    candidate["functions"][0]["named_parameters"] = {"strict": "BOOLEAN", "mode": "VARCHAR"}
    assert not compare(baseline, candidate)["changed"]
    candidate["functions"][0]["named_parameters"]["mode"] = "BOOLEAN"
    assert compare(baseline, candidate)["changed"] == ["reader"]
    candidate = json.loads(json.dumps(baseline))
    candidate["functions"][0]["parameters"].reverse()
    assert compare(baseline, candidate)["changed"] == ["reader"]


def test_rejected_validation_does_not_touch_the_rng(db):
    """switch evaluates its MAP argument at bind time without a foldability check; a caller-authored
    switch is rejected before binding, so the setseed inside it never runs during validation."""
    db.execute("SELECT setseed(0.1)")
    result = validate(db, "SELECT switch(1, MAP {1: setseed(0.5)})")
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "switch", result
    draws = [db.execute("SELECT random()").fetchone()[0] for _ in range(3)]
    db.execute("SELECT setseed(0.1)")
    assert draws == [db.execute("SELECT random()").fetchone()[0] for _ in range(3)]


@pytest.mark.parametrize("sql, name", [
    ("SELECT current_catalog()", "current_catalog"),
    ("SELECT get_block_size('memory')", "get_block_size"),
    ("SELECT pg_catalog.pg_get_viewdef(0)", "pg_get_viewdef"),
    ("SELECT * FROM histogram('t', x)", "histogram"),
    ("SELECT * FROM histogram_values('t', x)", "histogram_values"),
    ("SELECT list_aggregate([1,2], 'sum')", "list_aggregate"),
])
def test_reviewed_macro_and_dispatch_names(db, sql, name):
    db.execute("CREATE TABLE t AS SELECT 1 x")
    # Verify both the caller-authored serialized spelling and the pinned executable expansion.
    serialized = json.loads(db.execute("SELECT json_serialize_sql(?)", [sql]).fetchone()[0])
    assert not serialized["error"]
    def names(value):
        if isinstance(value, dict):
            return ({value["function_name"]} if "function_name" in value else set()).union(
                *(names(child) for child in value.values()))
        if isinstance(value, list):
            return set().union(*(names(child) for child in value))
        return set()
    assert name in names(serialized)
    db.execute(sql).fetchall()
    result = validate(db, sql)
    assert result["code"] == "forbidden" and result["error_message"] == ""
    assert any(v["rule"] == "function" and v["function_name"] == name for v in result["violations"])
