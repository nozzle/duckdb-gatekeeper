"""Verify candidate collector locks and reconstruct stages offline; standard library only."""
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


def verify():
    qualified_report = verify_collection_report(ROOT)
    verify_historical_report(ROOT, qualified_report)
    base, lock, summary = read("base.json"), read("lock.json"), read("summary.json")
    collection = read("collection.json")
    discovery = read("evidence/discovery.json")
    assert base["engine"] == lock["engine"] == collection["engine"]
    engine = base["engine"]
    assert (engine["library_version"], engine["source_id"], engine["platform"], engine["python_package_version"]) == (
        "v2.0.0-alpha42986", "d4e72566aa", "osx_arm64", "2.0.0.dev2609221243")
    assert digest(base) == lock["base_sha256"] == summary["base_sha256"]
    assert summary["collector_sha256"] == collection["collector_sha256"]
    for name, expected in collection["input_files_sha256"]["replay"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected
    assert hashlib.sha256((ROOT / "lock.json").read_bytes()).hexdigest() == collection["input_files_sha256"]["discovery"]["lock.json"]
    assert summary["mode"] == "verified" and summary["evidence_kind"] == "collector_locked_replay"
    assert len(summary["extensions"]) == 29
    assert set(summary["extensions"]) == set(lock["extensions"]) == set(discovery["extensions"])
    assert collections.Counter(summary["extensions"].values()) == {"ok": 25, "unavailable": 4}
    union = collections.Counter(json.dumps(row, sort_keys=True) for row in base["functions"])
    verified_stages, verified_setups = 0, []
    for name, status in summary["extensions"].items():
        result, pin = read(name + ".json"), lock["extensions"][name]
        assert result["status"] == status == pin["status"]
        assert result["schema_version"] == base["schema_version"] == lock["schema_version"] == 2
        assert result["capture_protocol"] == base["capture_protocol"] == lock["capture_protocol"]
        assert result["mode"] == "verified" and result["engine"] == engine
        assert result["base_sha256"] == digest(base)
        assert result["initial_extensions"] == base["loaded_extensions"]
        assert result["load_names"] == pin["load_names"]
        assert result["install_names"] == pin["install_names"]
        assert result["artifacts"] == pin["artifacts"]
        for artifact in result["artifacts"]:
            inv = next(n for n, p in lock["extensions"].items() if p["resolved_name"] == artifact["name"])
            evidence = read("evidence/" + inv + ".json")
            download = next(a for a in evidence["attempts"] if a.get("result") == "downloaded")
            assert artifact["sha256"] == download["decompressed_sha256"]
            assert artifact["download_sha256"] == download["compressed_sha256"]
            assert artifact["url"] == download["url"]
            assert artifact["bytes"] == download["decompressed_bytes"]
            assert artifact["version"] == download["footer"]["extension_version"]
            if "repository" in evidence["source"]:
                assert evidence["source"]["revision"].startswith(artifact["version"])
        observed = discovery["extensions"][name]
        if status == "unavailable":
            assert result["error"] == {"code": "artifact_not_in_lock"}
            assert observed["error"] == {"code": "http_error", "http_status": 404}
            assert len(result["stages"]) == 1
            assert all(a["name"] != result["resolved_name"] for a in result["artifacts"])
            assert result["stages"][0]["functions_sha256"] == digest(base["functions"])
            continue
        assert observed["stages_sha256"] == result["stages_sha256"]
        assert digest(result["stages"]) == result["stages_sha256"] == pin["stages_sha256"]
        assert [s["load_name"] for s in result["stages"][1:]] == result["load_names"]
        assert result["stages"][-1]["stage"] == "target"
        assert all(s["stage"] == "dependency" for s in result["stages"][1:-1])
        rows = base["functions"]
        for stage in result["stages"]:
            if "functions" in stage:
                rows = apply_delta(rows, stage["functions"])
            assert digest(rows) == stage["functions_sha256"]
            verified_stages += 1
        assert rows == apply_delta(base["functions"], result["functions"])
        assert len(rows) == result["function_count"]
        assert result["stages"][-1]["loaded_extensions"] == result["loaded_extensions"]
        expected_dependencies = sorted(e["name"] for e in result["loaded_extensions"]
                                       if e not in base["loaded_extensions"] and e["name"] != result["resolved_name"])
        assert result["dependencies_loaded"] == expected_dependencies
        verified_setups.append({"inventory": name, "load_names": result["load_names"],
                                "dependencies_loaded": expected_dependencies})
        union |= collections.Counter(json.dumps(row, sort_keys=True) for row in rows)
    identities = {(r["catalog"].lower(), tuple(p.lower() for p in r["schema_path"]), r["name"].lower(), r["kind"])
                  for r in (json.loads(key) for key in union)}
    assert len(identities) == qualified_report["union_qualified_identities"]
    assert sum(union.values()) == qualified_report["union_signatures"]
    repo = ROOT.parents[2]
    for relative, expected in collection["historical_inputs_sha256"].items():
        assert hashlib.sha256((repo / relative).read_bytes()).hexdigest() == expected
    for path in ROOT.rglob("*"):
        if path.is_file() and path.suffix in {".md", ".json"}:
            assert not any(value in path.read_text() for value in ["/Users/", "/private/var/", "/var/folders/"])
    return {"inventories_checked": 29, "verified_runtime_setups": verified_setups,
            "verified_registration_stages": verified_stages, "unavailable": 4,
            "stage_and_artifact_lock_checks": "passed", "dependency_attribution_checks": "passed",
            "historical_input_hashes": "unchanged", "personal_absolute_path_scan": "passed"}


if __name__ == "__main__":
    result = verify()
    print(f"Verified {len(result['verified_runtime_setups'])} runtime setups, "
          f"{result['verified_registration_stages']} registration stages and 4 unavailable outcomes; "
          "ordered locks, artifact hashes, dependency attribution and historical input hashes match.")
