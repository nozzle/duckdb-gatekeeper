"""Validated source inventories; importing this module never loads DuckDB extensions."""
import json
from pathlib import Path
from versions import SUPPORTED_DUCKDB

ROOT = Path(__file__).resolve().parents[1]


def schema_available():
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        return False
    return True


def load(root=ROOT, schema=True):
    """Load and check the reviewed inventories.

    ``schema=True`` (the default for tests, audits, and review tooling) requires the jsonschema
    package and validates every file against inventories/schema.json. Distribution builds run
    generate.py with only the standard library available, so they pass ``schema=False`` and rely
    on the structural checks below plus the schema validation CI performs on the same commit.
    """
    validator = None
    if schema:
        try:
            from jsonschema import Draft202012Validator
        except ImportError as error:
            raise SystemExit("Inventory validation requires jsonschema; install it with "
                             "python -m pip install -r requirements-inventory.txt using the build's Python interpreter") from error
        validator = Draft202012Validator(json.loads((root / "inventories/schema.json").read_text()))
    paths = [root / "inventories/core.json", *sorted((root / "inventories/extensions").glob("*.json"))]
    entries = {}
    for path in paths:
        entry = json.loads(path.read_text())
        if validator is not None:
            errors = sorted(validator.iter_errors(entry), key=lambda error: str(list(error.path)))
            if errors:
                raise ValueError(f"invalid inventory {path.name}: {errors[0].message}")
        for key in ["name", "reviewed_duckdb", "compute", "elevated"]:
            if key not in entry:
                raise ValueError(f"invalid inventory {path.name}: missing {key}")
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
