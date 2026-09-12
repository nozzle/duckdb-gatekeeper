"""One-time baseline schema upgrade, verifying named-order is the only change."""
import json
from collections import Counter
from audit_inventory import capture
from inventory import ROOT

path = ROOT / "inventories/baselines/duckdb-1.5.5.json"
old = json.loads(path.read_text())
new = capture()

def comparable(snapshot):
    result = []
    for original in snapshot["functions"]:
        entry = dict(original)
        if entry["kind"] == "table":
            entry["parameters"] = sorted(entry["parameters"] + list(entry.pop("named_parameters", {}).values()))
        result.append(json.dumps(entry, sort_keys=True))
    return Counter(result)

assert old["duckdb_version"] == new["duckdb_version"]
assert json.dumps(old["loaded_extensions"]) == json.dumps(new["loaded_extensions"])
assert comparable(old) == comparable(new), "Unexpected signature changes; review separately"
path.write_text(json.dumps(new, indent=2) + "\n")
