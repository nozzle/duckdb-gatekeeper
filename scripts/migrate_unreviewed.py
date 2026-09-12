"""Record explicitly unreviewed baseline names; never admit them to defaults."""
import json
import argparse
from inventory import ROOT, load
from versions import BASELINE_FILENAME

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="explicitly write the proposed unreviewed names")
    args = parser.parse_args()
    entries, _ = load(ROOT)
    snapshot = json.loads((ROOT / "inventories/baselines" / BASELINE_FILENAME).read_text())
    known = set(n for e in entries.values() for group in ["compute", "elevated"] for n in e[group])
    core = entries["core"]
    core["unreviewed"] = sorted({row["name"].lower() for row in snapshot["functions"]} - known)
    if args.write:
        (ROOT / "inventories/core.json").write_text(json.dumps(core, indent=2) + "\n")
    else:
        print(json.dumps(core["unreviewed"], indent=2))
        print("Dry run; pass --write to update core.json")


if __name__ == "__main__":
    main()
