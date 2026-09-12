"""Already-applied baseline migration, retained to test its verification invariant.

Running this on the current baseline verifies the same schema; --write is required to write.
"""
import json
import argparse
from collections import Counter
from audit_inventory import capture
from inventory import ROOT
from versions import BASELINE_FILENAME

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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write only after verifying unchanged signatures")
    args = parser.parse_args()
    path = ROOT / "inventories/baselines" / BASELINE_FILENAME
    old = json.loads(path.read_text())
    new = capture()
    verify_migration(old, new)
    if args.write:
        path.write_text(json.dumps(new, indent=2) + "\n")
    else:
        print("Migration verified; dry run (pass --write to write the baseline)")


if __name__ == "__main__":
    main()
