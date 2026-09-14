"""Validated source inventories; importing this module never loads DuckDB extensions."""
import json
from pathlib import Path
import re
import schema_check
from versions import SUPPORTED_DUCKDB, SUPPORTED_DUCKDB_REVISION

ROOT = Path(__file__).resolve().parents[1]


def check_sources(entries, root=ROOT):
    """Cross-check reviewed implementation URLs against the pinned engine's descriptors."""
    engine = f"https://github.com/duckdb/duckdb/tree/{SUPPORTED_DUCKDB_REVISION}"
    aliases = {name: name + "_scanner" for name in ("mysql", "postgres", "sqlite", "odbc")}
    for name, entry in entries.items():
        if name == "motherduck":
            if entry["compute"]:
                raise ValueError("Binary-only MotherDuck review cannot grant defaults")
            continue
        # UI is distributed separately and has no descriptor in this DuckDB checkout.
        # Require a source pin, but do not pretend the engine verifies that independent revision.
        if name == "ui":
            if not re.fullmatch(r"https://github.com/duckdb/duckdb-ui/tree/[0-9a-f]{40}", entry["source"]):
                raise ValueError("UI requires an independently reviewed source pin")
            continue
        if name == "core":
            expected = engine
        else:
            descriptor = root / "duckdb/.github/config/extensions" / (aliases.get(name, name) + ".cmake")
            if not descriptor.is_file() and not (root / "duckdb/extension" / name / "CMakeLists.txt").is_file():
                raise ValueError("Missing DuckDB extension source/descriptor: " + name)
            text = descriptor.read_text() if descriptor.is_file() else ""
            text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
            repositories = set(re.findall(r"\bGIT_URL\s+(https://\S+)", text))
            revisions = set(re.findall(r"\bGIT_TAG\s+(\S+)", text))
            if len(repositories) > 1 or len(revisions) > 1:
                raise ValueError("Ambiguous platform-conditional extension descriptor: " + name)
            if repositories:
                if not revisions or not re.fullmatch(r"[0-9a-f]{40}", next(iter(revisions))):
                    raise ValueError("Unpinned extension descriptor: " + name)
                expected = next(iter(repositories)).removesuffix(".git") + "/tree/" + next(iter(revisions))
            else:
                expected = engine + "/extension/" + name
        if entry["source"] != expected:
            raise ValueError(f"Reviewed source disagrees with pinned DuckDB descriptor: {name}: expected {expected}")


def load(root=ROOT):
    """Load and check the reviewed inventories against inventories/schema.json.

    Validation uses the standard-library validator in schema_check.py so that generation works in
    the community distribution images, which provide no third-party Python packages. The test
    suite cross-checks that validator against the jsonschema package.
    """
    schema = json.loads((root / "inventories/schema.json").read_text())
    paths = [root / "inventories/core.json", *sorted((root / "inventories/extensions").glob("*.json"))]
    entries = {}
    for path in paths:
        entry = json.loads(path.read_text())
        try:
            schema_check.validate(schema, entry)
        except schema_check.ValidationError as error:
            raise ValueError(f"invalid inventory {path.name}: {error.message}") from error
        name = entry["name"]
        if name in entries:
            raise ValueError(f"duplicate inventory: {name}")
        if entry["reviewed_duckdb"] != SUPPORTED_DUCKDB:
            raise ValueError(f"missing or incompatible review metadata: {name}")
        groups = {group: entry.get(group, []) for group in ["compute", "elevated", "unreviewed"]}
        groups.update({f"groups.{group}": names for group, names in entry.get("groups", {}).items()})
        for group, names in groups.items():
            if names != sorted(set(names)) or any(not n or n != n.strip().lower() for n in names):
                raise ValueError(f"{name}.{group} must contain sorted, unique, normalized names")
        if set(entry["compute"]) & set(entry["elevated"]):
            raise ValueError(f"conflicting classifications in {name}")
        if set(entry.get("unreviewed", [])) & (set(entry["compute"]) | set(entry["elevated"])):
            raise ValueError(f"reviewed/unreviewed conflict in {name}")
        entries[name] = entry
    compute = set(n for entry in entries.values() for n in entry["compute"])
    elevated = set(n for entry in entries.values() for n in entry["elevated"])
    unreviewed = set(n for entry in entries.values() for n in entry.get("unreviewed", []))
    conflicts = compute & elevated
    if conflicts:
        raise ValueError("cross-inventory classification conflicts: " + ", ".join(sorted(conflicts)))
    if unreviewed & (compute | elevated):
        raise ValueError("cross-inventory reviewed/unreviewed conflict")
    core = entries["core"]
    if set(n for names in core["groups"].values() for n in names) != set(core["compute"]):
        raise ValueError("core groups and compute classification disagree")
    return entries, sorted(compute)
