"""Read canonical release metadata without importing development dependencies."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def load_versions(root=ROOT):
    values = {}
    for line in (root / "versions.cmake").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
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


def reviewed_duckdb(root=ROOT):
    """The engine the core inventory was reviewed against; historical provenance, not a build pin."""
    version = json.loads((root / "inventories/core.json").read_text()).get("reviewed_duckdb")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError(f"Invalid core.json reviewed_duckdb: {version!r}")
    return version


VERSIONS = load_versions()
EXTENSION_VERSION = VERSIONS["GATEKEEPER_VERSION"]
# Release build defaults only; these do not restrict the engine used by community builds.
SUPPORTED_DUCKDB = VERSIONS["GATEKEEPER_DUCKDB_VERSION"]
SUPPORTED_DUCKDB_REVISION = VERSIONS["GATEKEEPER_DUCKDB_REVISION"]
# Historical inventory provenance is independent of the release build engine.
REVIEWED_DUCKDB = reviewed_duckdb()
BASELINE_FILENAME = f"duckdb-{REVIEWED_DUCKDB}.json"
