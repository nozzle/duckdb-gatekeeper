"""Offline adapters and hash-checked reconstruction of staged collector evidence.

No DuckDB import, extension loading, or permission generation belongs here.
"""
import collections
import hashlib
import json
from pathlib import Path


PROTOCOL = "gatekeeper-isolated-staged-capture-v2"


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def snapshot(value):
    """Adapt full snapshots without inventing qualification or changing raw signatures."""
    require(isinstance(value.get("functions"), list),
            "Expected a full function snapshot; extension deltas require --collection DIR --extension NAME")
    version = value.get("duckdb_version", value.get("engine", {}).get("library_version"))
    require(isinstance(version, str), "Snapshot requires duckdb_version or engine.library_version")
    extensions = value.get("loaded_extensions", [])
    extensions = sorted([[entry["name"], entry["version"]] if isinstance(entry, dict) else list(entry)
                         for entry in extensions])
    return {**value, "duckdb_version": version, "loaded_extensions": extensions}


def apply_delta(before, delta):
    """Multiset subtraction preserves duplicate overloads and capture ordering."""
    rows = collections.Counter(json.dumps(row, sort_keys=True) for row in before)
    removed = delta["removed"] + [row for group in delta["changed"] for row in group["before"]]
    added = delta["added"] + [row for group in delta["changed"] for row in group["after"]]
    for row in removed:
        key = json.dumps(row, sort_keys=True)
        require(rows[key] > 0, "delta removes a missing signature")
        rows[key] -= 1
    rows.update(json.dumps(row, sort_keys=True) for row in added)
    return [json.loads(key) for key in sorted(rows) for _ in range(rows[key])]


def reconstruct_collection(path):
    """Return (adapted base, outcomes) after verifying every recorded stage and lock.

    Each outcome has its original metadata and a snapshots list in recorded stage
    order. Incomplete outcomes retain observed stages but are never successful targets.
    Hashes establish consistency with committed metadata, not binary authenticity.
    """
    path = Path(path)
    if path.name == "collection.json":
        path = path.parent

    def read(name):
        return json.loads((path / name).read_text())

    base, lock, summary = read("base.json"), read("lock.json"), read("summary.json")
    base_hash = digest(base)
    require(base.get("snapshot_type") == "base", "Expected collector base")
    require(base_hash == lock["base_sha256"] == summary["base_sha256"], "base hash mismatch")
    require(base["engine"] == lock["engine"], "lock engine mismatch")
    require(set(summary["extensions"]) == set(lock["extensions"]), "lock/summary extension mismatch")
    for document in (base, lock, summary):
        require(document["schema_version"] == 2 and document["capture_protocol"] == PROTOCOL,
                "Unsupported collection protocol/schema")
    outcomes = {}
    for name, status in sorted(summary["extensions"].items()):
        require(name and all(c in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in name),
                "Invalid inventory filename")
        result, pin = read(name + ".json"), lock["extensions"][name]
        require(result["inventory"] == name and result["snapshot_type"] == "extension_delta",
                f"{name}: invalid extension delta")
        require(result["schema_version"] == 2 and result["capture_protocol"] == PROTOCOL,
                f"{name}: unsupported protocol/schema")
        require(result["base_sha256"] == base_hash and result["engine"] == base["engine"],
                f"{name}: base/engine mismatch")
        require(result["mode"] == summary["mode"], f"{name}: collection mode mismatch")
        require(result["status"] == status == pin["status"], f"{name}: status mismatch")
        for field in ("install_names", "load_names", "artifacts", "resolved_name", "repository"):
            require(result[field] == pin[field], f"{name}: lock {field} mismatch")
        if "initial_extensions" in result:
            require(result["initial_extensions"] == base["loaded_extensions"], f"{name}: initial extensions mismatch")
        stages = result.get("stages", [])
        snapshots, rows = [], base["functions"]
        for index, stage in enumerate(stages):
            if index == 0:
                require(stage["stage"] == "before" and "functions" not in stage,
                        f"{name}: invalid initial stage")
                require(stage["loaded_extensions"] == base["loaded_extensions"],
                        f"{name}: initial stage extensions mismatch")
            else:
                require(stage["stage"] in {"dependency", "target"} and "functions" in stage,
                        f"{name}: invalid load stage")
                rows = apply_delta(rows, stage["functions"])
            require(digest(rows) == stage["functions_sha256"], f"{name}: stage {index} function hash mismatch")
            snapshots.append(snapshot({"engine": base["engine"], "functions": rows,
                                       "loaded_extensions": stage["loaded_extensions"]}))
        if status == "ok":
            require(len(stages) >= 2 and stages[-1]["stage"] == "target"
                    and all(s["stage"] == "dependency" for s in stages[1:-1]), f"{name}: missing target stage")
            require([s["load_name"] for s in stages[1:]] == result["load_names"], f"{name}: stage load order mismatch")
            require(digest(stages) == result["stages_sha256"] == pin["stages_sha256"], f"{name}: stages hash mismatch")
            require(rows == apply_delta(base["functions"], result["functions"]), f"{name}: final delta mismatch")
            require(len(rows) == result["function_count"], f"{name}: function count mismatch")
            require(stages[-1]["loaded_extensions"] == result["loaded_extensions"], f"{name}: final extensions mismatch")
            dependencies = sorted(e["name"] for e in result["loaded_extensions"]
                                  if e not in base["loaded_extensions"] and e["name"] != result["resolved_name"])
            require(dependencies == result["dependencies_loaded"], f"{name}: dependencies mismatch")
        else:
            require(not any(s["stage"] == "target" for s in stages) and "functions" not in result,
                    f"{name}: incomplete outcome claims a target snapshot")
        outcomes[name] = {"metadata": result, "snapshots": snapshots}
    return snapshot(base), outcomes


def union_snapshot(snapshots):
    """Multiset union of independent setups, not a claim of a combined live catalog."""
    rows = collections.Counter()
    for value in snapshots:
        rows |= collections.Counter(json.dumps(row, sort_keys=True) for row in value["functions"])
    return {"duckdb_version": snapshots[0]["duckdb_version"],
            "functions": [json.loads(key) for key in sorted(rows) for _ in range(rows[key])]}
