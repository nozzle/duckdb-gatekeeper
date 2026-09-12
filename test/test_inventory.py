import json
import sys
import shutil
import pytest

from test_gatekeeper import ROOT, check, db

sys.path.insert(0, str(ROOT / "scripts"))
from inventory import load
from audit_inventory import compare, coverage


def test_complete_default_inventory(db):
    entries, names = load()
    assert len(entries) == 30
    assert len(names) == 864
    for name in names:
        quoted = '"' + name.replace('"', '""') + '"'
        result = check(db, f"SELECT {quoted}(1)")
        assert result["allowed"], (name, result)
        assert not check(db, f"SELECT {quoted}(1)", {"blocked_functions": [name]})["allowed"]


def test_nondefault_inventory(db):
    entries, defaults = load()
    for entry in entries.values():
        for name in entry["elevated"] + entry.get("unreviewed", []):
            assert name not in defaults
            sql = 'SELECT "' + name.replace('"', '""') + '"(1)'
            assert not check(db, sql)["allowed"], name


def test_audit_deltas():
    baseline = json.loads((ROOT / "inventories/baselines/duckdb-1.5.5.json").read_text())
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
