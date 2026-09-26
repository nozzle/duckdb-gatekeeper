"""Offline verification of compact release evidence; Python standard library only."""
import collections
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[2] / "scripts"))
from audit_inventory import verify_collection_report, verify_historical_report
from inventory_capture import apply_delta, digest


def read(name):
    return json.loads((ROOT / name).read_text())


def functions_for(ref, base):
    if ref == "base.json":
        return base["functions"]
    filename, marker, index = ref.partition("#stage=")
    result = read(filename)
    if not marker:
        return apply_delta(base["functions"], result["functions"])
    rows = base["functions"]
    for stage in result["stages"][:int(index) + 1]:
        if "functions" in stage:
            rows = apply_delta(rows, stage["functions"])
    return rows


def verify():
    report = verify_collection_report(ROOT)
    verify_historical_report(ROOT, report)
    base, lock, summary = read("base.json"), read("lock.json"), read("summary.json")
    original, collection = read("original-evidence.json"), read("collection.json")
    assert digest(base) == lock["base_sha256"] == summary["base_sha256"]
    assert len(summary["extensions"]) == 29
    assert collections.Counter(summary["extensions"].values()) == {"ok": 28, "skipped": 1}
    verified_stages = 0
    for name, status in summary["extensions"].items():
        result, pin = read(name + ".json"), lock["extensions"][name]
        assert result["status"] == status == pin["status"]
        assert result["mode"] == "verified"
        assert result["schema_version"] == base["schema_version"] == lock["schema_version"] == 2
        assert result["capture_protocol"] == base["capture_protocol"] == lock["capture_protocol"]
        assert result["base_sha256"] == digest(base)
        assert result["install_names"] == pin["install_names"]
        assert result["load_names"] == pin["load_names"]
        assert result["artifacts"] == pin["artifacts"]
        assert result["engine"] == base["engine"]
        for artifact in result["artifacts"]:
            if artifact["name"] == "odbc_scanner":
                assert artifact == collection["final_odbc_artifact_metadata"]["artifact"]
                continue
            source = next(entry["artifact"] for entry in original["extensions"].values()
                          if entry["artifact"]["artifact_name"] == artifact["name"])
            assert artifact["sha256"] == source["decompressed_sha256"]
            assert artifact["download_sha256"] == source["compressed_sha256"]
            assert artifact["url"] == source["url"]
            assert artifact["version"] == source["footer"]["extension_version"]
        if status != "ok":
            assert name == "motherduck" and len(result["stages"]) == 1
            continue
        rows = base["functions"]
        for stage in result["stages"]:
            if "functions" in stage:
                rows = apply_delta(rows, stage["functions"])
            assert digest(rows) == stage["functions_sha256"]
            verified_stages += 1
        assert rows == apply_delta(base["functions"], result["functions"])
        assert len(rows) == result["function_count"]
        assert digest(result["stages"]) == result["stages_sha256"] == pin["stages_sha256"]
    for expected, record in original["original_full_snapshots"].items():
        value = {**record["metadata"], "functions": functions_for(record["functions_ref"], base)}
        encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        assert hashlib.sha256(encoded).hexdigest() == expected
    assert len(original["original_full_snapshots"]) == 37
    repo = ROOT.parents[2]
    for relative, key in [("inventories/baselines/duckdb-1.5.5.json", "baseline_sha256"),
                          ("inventories/default_identities.json", "default_mapping_sha256")]:
        assert hashlib.sha256((repo / relative).read_bytes()).hexdigest() == collection[key]
    for path in ROOT.glob("*.json"):
        text = path.read_text()
        assert not any(value in text for value in ["/Users/", "/private/var/", "/var/folders/"])
    print(f"Verified 29 outcomes, {verified_stages} stages, ordered locks and artifact provenance; "
          "reconstructed all 37 original full-snapshot SHA-256 values exactly.")


if __name__ == "__main__":
    verify()
