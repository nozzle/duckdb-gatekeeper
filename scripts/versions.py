"""Read canonical release metadata without importing development dependencies."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def load_versions(root=ROOT):
    values = {}
    for line in (root / "versions.cmake").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r'set\((GATEKEEPER_[A-Z_]+) "([^"]+)"\)', line)
        if not match or match[1] in values:
            raise ValueError("Invalid or duplicate version metadata: " + line)
        values[match[1]] = match[2]
    expected = {"GATEKEEPER_VERSION", "GATEKEEPER_DUCKDB_VERSION", "GATEKEEPER_DUCKDB_REVISION"}
    if set(values) != expected:
        raise ValueError("versions.cmake must define exactly " + ", ".join(sorted(expected)))
    for key, value in values.items():
        pattern = r"[0-9a-f]{40}" if key.endswith("REVISION") else r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
        if not re.fullmatch(pattern, value):
            raise ValueError("Invalid version metadata: " + key)
    return values


VERSIONS = load_versions()
EXTENSION_VERSION = VERSIONS["GATEKEEPER_VERSION"]
SUPPORTED_DUCKDB = VERSIONS["GATEKEEPER_DUCKDB_VERSION"]
SUPPORTED_DUCKDB_REVISION = VERSIONS["GATEKEEPER_DUCKDB_REVISION"]
BASELINE_FILENAME = f"duckdb-{SUPPORTED_DUCKDB}.json"
