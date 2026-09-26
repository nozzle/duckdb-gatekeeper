"""Committed capture regressions: offline, no installed extension or source checkout needed."""
import copy
import json
import shutil
import subprocess
import sys

import pytest

from audit_inventory import (collection_report, compare, identity_coverage, qualified_identities,
                             verify_collection_report, verify_historical_report)
from inventory import ROOT, identity_key, load, load_default_identities, load_default_mapping
from inventory_capture import apply_delta, reconstruct_collection, snapshot


COLLECTIONS = sorted((ROOT / "inventories/runtime").glob("*/collection.json"))


@pytest.fixture(scope="module", params=COLLECTIONS, ids=lambda path: path.parent.name)
def collection(request):
    path = request.param.parent
    base, outcomes = reconstruct_collection(path)
    return path, base, outcomes, collection_report(path)


def test_committed_reports_are_recomputed_and_historical_hashes_still_match(collection):
    path, _, _, report = collection
    assert verify_collection_report(path) == report
    verify_historical_report(path, report)
    result = subprocess.run([sys.executable, "-S", str(path / "reconstruct.py")], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_base_and_extension_cli_use_offline_supported_adapters(collection):
    path, base, outcomes, _ = collection
    historical = json.loads((ROOT / "inventories/baselines/duckdb-1.5.5.json").read_text())
    raw = json.loads((path / "base.json").read_text())
    before = copy.deepcopy(raw)
    assert compare(historical, raw) == compare(historical, base)
    assert raw == before
    # No site packages are available, so these commands cannot silently capture a runtime.
    for args in (["--candidate", str(path / "base.json")],
                 ["--collection", str(path / "collection.json"), "--extension", "excel"]):
        result = subprocess.run([sys.executable, "-S", str(ROOT / "scripts/audit_inventory.py"), *args],
                                check=True, capture_output=True, text=True)
        report = json.loads(result.stdout)
        assert report["qualified_drift"]["candidate_qualified"]
        assert not report["qualified_drift"]["baseline_qualified"]
    with pytest.raises(ValueError, match="--collection"):
        snapshot(outcomes["excel"]["metadata"])


def test_optional_extension_source_map_kinds_match_committed_targets(collection):
    _, _, outcomes, _ = collection
    entries, _ = load()
    defaults = load_default_identities()
    for name, outcome in outcomes.items():
        if outcome["metadata"]["status"] != "ok":
            continue
        target = outcome["snapshots"][-1]
        source_names = set(entries[name]["compute"])
        expected = {identity_key(row) for row in defaults if row["name"] in source_names}
        observed = {key for key in qualified_identities(target) if key[2] in source_names}
        # These exact candidate removals retain their source-backed grants. There is no
        # broad absent-extension/kind exemption, and no runtime-to-permission promotion.
        missing = set()
        if target["duckdb_version"] == "v2.0.0-alpha42986":
            missing = {("system", ("main",), n, "scalar")
                       for n in {"icu_collate_yue", "icu_collate_yue_cn", "st_snap"} & source_names}
        assert expected - observed == missing, name
        assert observed - expected == set(), name


def test_version_specific_intrinsics_and_reporting_labels_remain_explicit(collection):
    _, base, _, report = collection
    missing = {identity_key(row) for row in report["defaults_not_observed"]}
    windows = {identity_key(row) for row in load_default_identities() if row["type"] == "window"}
    scalar_unnest = {("system", ("main",), "unnest", "scalar")}
    if base["duckdb_version"] == "v1.5.5":
        expected = scalar_unnest | windows | {("system", ("main",), n, "scalar")
                                             for n in ("round_even", "roundbankers")}
        assert {identity_key(row) for row in report["default_names_at_ungranted_identities"]} == {
            (c, s, n, "aggregate") for c, s, n, _ in windows}
        assert set(report["reporting_discrepancies"][0]["names"]) == {row[2] for row in windows}
    else:
        expected = scalar_unnest | {("system", ("main",), n, "macro") for n in ("round_even", "roundbankers")} | {
            ("system", ("main",), n, "scalar") for n in ("icu_collate_yue", "icu_collate_yue_cn", "st_snap")}
        assert report["reporting_discrepancies"] == []
        assert report["default_names_at_ungranted_identities"] == []
    assert missing == expected
    grants = {identity_key(row) for row in load_default_identities()}
    assert {identity_key(row) for row in report["observed_default_identities"]} == grants - expected


def test_excel_equal_count_wrong_kind_and_unknown_addition_are_not_grants(collection):
    _, _, outcomes, _ = collection
    target = copy.deepcopy(outcomes["excel"]["snapshots"][-1])
    entries, _ = load()
    defaults, mapping = load_default_identities(), load_default_mapping()
    original_count = len(qualified_identities(target))
    next(row for row in target["functions"] if row["name"] == "excel_text")["kind"] = "table"
    assert len(qualified_identities(target)) == original_count
    report = identity_coverage(target, defaults, entries, mapping)
    wrong = {"catalog": "system", "schema_path": ["main"], "name": "excel_text", "type": "table"}
    assert wrong in report["default_names_at_ungranted_identities"]
    assert {**wrong, "type": "scalar"} in report["defaults_not_observed"]
    target["functions"].append({"catalog": "system", "schema_path": ["main"], "name": "new_excel_probe", "kind": "scalar"})
    assert "new_excel_probe" in identity_coverage(target, defaults, entries, mapping)["unclassified_runtime_names"]
    assert defaults == load_default_identities() and not any(row["name"] == "new_excel_probe" for row in defaults)


def test_equal_count_source_map_kind_change_fails_capture_crosscheck(collection, tmp_path):
    path, _, _, original = collection
    shutil.copytree(ROOT / "inventories", tmp_path / "inventories")
    mapping_path = tmp_path / "inventories/default_identities.json"
    mapping = json.loads(mapping_path.read_text())
    next(group for group in mapping["grants"] if group["evidence"] == "excel")["type"] = "table"
    mapping_path.write_text(json.dumps(mapping))
    changed = collection_report(path, root=tmp_path)
    assert changed["compiled_defaults"] == original["compiled_defaults"]
    missing = changed["per_extension"]["excel"]["source_default_coverage"]["defaults_not_observed"]
    assert {row["name"] for row in missing} == {"excel_text", "text"}
    assert {row["type"] for row in missing} == {"table"}
    with pytest.raises(ValueError, match="report differs"):
        verify_collection_report(path, root=tmp_path)


@pytest.mark.parametrize("field", ["defaults_not_observed", "unclassified_runtime_names"])
def test_old_aggregate_report_equal_count_substitutions_are_rejected(collection, tmp_path, field):
    path, _, _, report = collection
    old = json.loads((path / "report.json").read_text())
    if field == "defaults_not_observed":
        old.get("qualified_source_mapping", old)[field][0]["name"] = "wrong_missing_default"
    else:
        old["unclassified_added_names" if "qualified_source_mapping" in old else field][0] = "wrong_unknown_name"
    (tmp_path / "report.json").write_text(json.dumps(old))
    with pytest.raises(ValueError, match="mismatch"):
        verify_historical_report(tmp_path, report)


@pytest.mark.parametrize("field", ["defaults_not_observed", "observed_default_identities", "unclassified_runtime_names",
                                   "default_names_at_ungranted_identities", "per_extension"])
def test_equal_count_report_mutations_fail_verification(collection, tmp_path, field):
    path, _, _, original = collection
    report = copy.deepcopy(original)
    if field == "per_extension":
        row = next(r for r in report[field]["excel"]["source_default_coverage"]["observed_default_identities"]
                   if r["name"] == "excel_text")
        row["type"] = "table"
    elif field == "unclassified_runtime_names":
        report[field][0] = "substituted_unknown_name"
    elif report[field]:
        report[field][0]["type"] = "table"
    else:
        report[field].append({"catalog": "system", "schema_path": ["main"], "name": "abs", "type": "table"})
    destination = tmp_path / "report.json"
    destination.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="report differs"):
        verify_collection_report(path, report_path=destination)


@pytest.mark.parametrize("mutation", ["base", "stage-row", "stage-hash", "stage-order", "final-delta", "lock"])
def test_reconstruction_rejects_tampering(collection, tmp_path, mutation):
    path, _, _, _ = collection
    shutil.copytree(path, tmp_path / "capture")
    root = tmp_path / "capture"
    filename = "base.json" if mutation == "base" else "lock.json" if mutation == "lock" else "excel.json"
    value = json.loads((root / filename).read_text())
    if mutation == "base":
        value["functions"][0]["kind"] = "table"
    elif mutation == "stage-row":
        value["stages"][-1]["functions"]["added"][0]["kind"] = "table"
    elif mutation == "stage-hash":
        value["stages"][-1]["functions_sha256"] = "0" * 64
    elif mutation == "stage-order":
        value["stages"].reverse()
    elif mutation == "final-delta":
        value["functions"]["added"][0]["kind"] = "table"
    else:
        value["extensions"]["excel"]["stages_sha256"] = "0" * 64
    (root / filename).write_text(json.dumps(value))
    with pytest.raises(ValueError):
        reconstruct_collection(root)


def test_multiset_delta_preserves_duplicate_signatures_and_rejects_underflow():
    row = {"name": "overloaded", "kind": "scalar"}
    delta = {"removed": [row], "added": [], "changed": []}
    assert apply_delta([row, row], delta) == [row]
    with pytest.raises(ValueError, match="missing signature"):
        apply_delta([], delta)
