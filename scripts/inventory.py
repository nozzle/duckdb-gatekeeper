"""Validated source inventories; importing this module never loads DuckDB extensions."""
import json
from pathlib import Path
import re
import subprocess
import schema_check

ROOT = Path(__file__).resolve().parents[1]


def identity_key(identity):
    return identity["catalog"], tuple(identity["schema_path"]), identity["name"], identity["type"]


def load_default_mapping(root=ROOT):
    """Validate the independently reviewed registration map, without consulting a runtime.

    Every historical compute name must have a source-backed identity or an explicit exclusion.
    Multiple kinds are allowed only when each is explicitly recorded; never infer one from a name.
    """
    entries, names = load(root)
    mapping = json.loads((root / "inventories/default_identities.json").read_text())
    schema = json.loads((root / "inventories/default_identities.schema.json").read_text())
    try:
        schema_check.validate(schema, mapping)
    except schema_check.ValidationError as error:
        raise ValueError("invalid default identity mapping: " + error.message) from error
    known = set(names)
    seen, excluded = set(), set()
    used_evidence = set()
    for group in mapping["grants"] + mapping["exclusions"]:
        evidence = group["evidence"]
        if evidence not in mapping["evidence"]:
            raise ValueError("unknown identity evidence: " + evidence)
        used_evidence.add(evidence)
        members = group["names"]
        if members != sorted(set(members)) or any(n != n.strip().lower() or "\0" in n for n in members):
            raise ValueError("identity names must be sorted, unique and normalized: " + evidence)
        if set(members) - known:
            raise ValueError("identity mapping contains non-compute names: " + ", ".join(sorted(set(members) - known)))
        owners = mapping["evidence"][evidence]["inventories"]
        if any(owner not in entries for owner in owners):
            raise ValueError("unknown identity evidence inventory: " + evidence)
        if set(members) - {n for owner in owners for n in entries[owner]["compute"]}:
            raise ValueError("identity evidence does not own compute names: " + evidence)
        if "reason" in group:
            if excluded & set(members):
                raise ValueError("duplicate identity exclusion")
            excluded.update(members)
            continue
        for name in members:
            key = identity_key({**group, "name": name})
            if key in seen:
                raise ValueError("duplicate/conflicting default identity: " + repr(key))
            seen.add(key)
    granted = {key[2] for key in seen}
    if granted & excluded:
        raise ValueError("conflicting granted/excluded identity names: " + ", ".join(sorted(granted & excluded)))
    missing = known - granted - excluded
    if missing:
        raise ValueError("missing default identity mapping: " + ", ".join(sorted(missing)))
    if used_evidence != set(mapping["evidence"]):
        raise ValueError("unused default identity evidence")
    discrepancies = set()
    for group in mapping["reporting_discrepancies"]:
        if group["evidence"] not in used_evidence or group["names"] != sorted(set(group["names"])):
            raise ValueError("invalid reporting discrepancy evidence/names")
        for name in group["names"]:
            actual = identity_key({**group, "name": name})
            reported = (*actual[:3], group["reported_type"])
            key = group["duckdb_version"], reported
            if actual not in seen or reported in seen or key in discrepancies:
                raise ValueError("conflicting reporting discrepancy: " + name)
            discrepancies.add(key)
    return mapping


def load_default_identities(root=ROOT):
    """Return sorted explicit {catalog, schema_path, name, type} grants (stdlib only)."""
    mapping = load_default_mapping(root)
    identities = [{"catalog": group["catalog"], "schema_path": list(group["schema_path"]),
                   "name": name, "type": group["type"]}
                  for group in mapping["grants"] for name in group["names"]]
    return sorted(identities, key=identity_key)


def check_sources(entries, root=ROOT, duckdb_source=None):
    """Optional provenance check against a checkout of the historical review engine."""
    source = duckdb_source if duckdb_source is not None else root / "duckdb"
    engine = ""
    if "core" in entries:
        engine = entries["core"]["source"]
        try:
            revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True,
                                               stderr=subprocess.PIPE).strip()
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError(f"Source check needs Git and a DuckDB checkout at {source}; clone with "
                             "--recurse-submodules or pass --source-checkout") from error
        if engine != "https://github.com/duckdb/duckdb/tree/" + revision:
            raise ValueError("Source check requires the historical review checkout; use --source-checkout")
    aliases = {name: name + "_scanner" for name in ("mysql", "postgres", "sqlite", "odbc")}
    for name, entry in entries.items():
        # Binary-only reviews (schema: binary_review) have no source descriptor in the engine checkout.
        if "binary_review" in entry:
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
            descriptor = source / ".github/config/extensions" / (aliases.get(name, name) + ".cmake")
            if not descriptor.is_file() and not (source / "extension" / name / "CMakeLists.txt").is_file():
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
