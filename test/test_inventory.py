import json
import sys
import shutil
import pytest

from test_gatekeeper import ROOT, check, db

sys.path.insert(0, str(ROOT / "scripts"))
from inventory import load
from audit_inventory import compare, coverage
from versions import BASELINE_FILENAME
from typed_helpers import never_bind_names


def test_never_bind_inventory_excluded_from_defaults():
    names = never_bind_names()
    _, defaults = load()
    assert names and not set(names) & set(defaults)


def test_complete_default_inventory(db):
    db.execute("SET autoinstall_known_extensions=false; SET autoload_known_extensions=false")
    entries, names = load()
    assert len(entries) == 30
    assert len(names) == 864
    for name in names:
        quoted = '"' + name.replace('"', '""') + '"'
        result = check(db, f"SELECT {quoted}(1)")
        assert result["code"] in {"ok", "binding"}, (name, result)
        assert not check(db, f"SELECT {quoted}(1)", {"blocked_functions": [name]})["allowed"]


def test_nondefault_inventory(db):
    entries, defaults = load()
    for entry in entries.values():
        for name in entry["elevated"] + entry.get("unreviewed", []):
            assert name not in defaults
            sql = 'SELECT "' + name.replace('"', '""') + '"(1)'
            assert not check(db, sql)["allowed"], name


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


@pytest.mark.parametrize("sql, name", [
    ("SELECT current_catalog()", "current_catalog"),
    ("SELECT ago(INTERVAL 1 DAY)::VARCHAR", "ago"),
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
    result = check(db, sql)
    assert result["code"] == "forbidden" and result["error_message"] == ""
    assert any(v["rule"] == "function" and v["function_name"] == name for v in result["violations"])
