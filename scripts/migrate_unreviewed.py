"""Record explicitly unreviewed baseline names; never admit them to defaults."""
import json
from inventory import ROOT, load

entries, defaults = load()
snapshot = json.loads((ROOT / "inventories/baselines/duckdb-1.5.5.json").read_text())
known = set(n for e in entries.values() for group in ["compute", "elevated"] for n in e[group])
core = entries["core"]
core["unreviewed"] = sorted({row["name"].lower() for row in snapshot["functions"]} - known)
core["unreviewed_reason"] = "Present in the initial runtime baseline but not classified by the migrated review. Excluded by default; human source review is required before promotion."
(ROOT / "inventories/core.json").write_text(json.dumps(core, indent=2) + "\n")
