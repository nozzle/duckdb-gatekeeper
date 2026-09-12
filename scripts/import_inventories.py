"""One-time migration from the reviewed Mosaic inventories; not part of the build."""
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
data = subprocess.check_output(
    ["go", "run", str(root / "scripts/import_inventories.go")], cwd=sys.argv[1], text=True
)
(root / "inventories").mkdir(exist_ok=True)
data = json.loads(data)
source = Path(sys.argv[1]) / "pkg/functionset"
provenance = "https://github.com/uwdata/mosaic/tree/3eb74ea8/packages/server/duckdb-server-go/pkg/functionset"
core = {
    "name": "core", "reviewed_duckdb": "1.5.5", "source": provenance + "/functionset.go",
    "notes": "Reviewed defaults migrated from Mosaic. Unlisted names remain excluded pending review.",
    "groups": data["core"], "compute": sorted(set(n for group in data["core"].values() for n in group)),
    "elevated": [],
}
(root / "inventories/core.json").write_text(json.dumps(core, indent=2) + "\n")
(root / "inventories/extensions").mkdir(exist_ok=True)
for name, groups in data["extensions"].items():
    comments = [line.strip()[3:] for line in (source / (name + ".go")).read_text().splitlines() if line.strip().startswith("// ")]
    entry = {"name": name, "reviewed_duckdb": "1.5.5", "source": provenance + "/" + name + ".go",
             "notes": comments, **groups}
    (root / "inventories/extensions" / (name + ".json")).write_text(json.dumps(entry, indent=2) + "\n")
