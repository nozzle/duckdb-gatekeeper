"""One-time baseline schema upgrade, verifying named-order is the only change."""
import json
from collections import Counter
from audit_inventory import capture
from inventory import ROOT

def verify_migration(old, new):
    if old["duckdb_version"] != new["duckdb_version"] or json.dumps(old["loaded_extensions"]) != json.dumps(new["loaded_extensions"]):
        raise ValueError("Runtime version changed; review separately")
    remaining = Counter(json.dumps(entry, sort_keys=True) for entry in new["functions"])
    for original in old["functions"]:
        matches = set()
        for encoded, count in remaining.items():
            if not count:
                continue
            candidate = json.loads(encoded)
            if original["kind"] != "table" or "named_parameters" in original:
                equal = original == candidate
            else:
                positional = candidate["parameters"]
                legacy = original["parameters"]
                metadata = {k: v for k, v in original.items() if k != "parameters"}
                candidate_metadata = {k: v for k, v in candidate.items() if k not in ("parameters", "named_parameters")}
                equal = (metadata == candidate_metadata and legacy[:len(positional)] == positional
                         and Counter(legacy[len(positional):]) == Counter(candidate.get("named_parameters", {}).values()))
            if equal:
                matches.add(encoded)
        if len(matches) != 1:
            raise ValueError("Changed or ambiguous signature; review separately: " + original["name"])
        remaining[matches.pop()] -= 1
    if any(remaining.values()):
        raise ValueError("Candidate contains additional signatures; review separately")


def main():
    path = ROOT / "inventories/baselines/duckdb-1.5.5.json"
    old = json.loads(path.read_text())
    new = capture()
    verify_migration(old, new)
    path.write_text(json.dumps(new, indent=2) + "\n")


if __name__ == "__main__":
    main()
