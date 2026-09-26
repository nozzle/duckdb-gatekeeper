"""Source-only default provenance and capture tooling tests; no Gatekeeper artifact needed."""
import copy
import json
import shutil
import subprocess
import sys

import pytest

from audit_inventory import capture_functions, compare, qualified_drift, reporting_discrepancies
from generate import header
from inventory import ROOT, identity_key, load, load_default_identities, load_default_mapping
import schema_check


def test_default_mapping_accounts_for_every_historical_name():
    _, names = load()
    mapping = load_default_mapping()
    identities = load_default_identities()
    excluded = {name for group in mapping["exclusions"] for name in group["names"]}
    granted = {identity["name"] for identity in identities}
    assert len(names) == 953
    assert len(identities) == 919 and len(granted) == 913 and len(excluded) == 40
    assert granted | excluded == set(names) and not granted & excluded
    assert identities == sorted(identities, key=identity_key)
    assert all(row["catalog"] == "system" and row["schema_path"] == ["main"] for row in identities)
    assert {"pg_typeof", "pg_conf_load_time", "has_table_privilege"} <= excluded
    kinds = lambda name: {row["type"] for row in identities if row["name"] == name}
    assert kinds("sum") == {"aggregate"}
    assert kinds("abs") == {"scalar"}
    assert kinds("row_number") == {"window"}
    assert kinds("unnest") == {"scalar", "table"}
    assert kinds("range") == {"scalar", "table"}
    assert kinds("parse_delta_filter_logline") == {"macro"}
    assert kinds("st_rotate") == {"macro"}
    assert kinds("st_memunion_agg") == {"aggregate"}
    assert kinds("round_even") == {"macro", "scalar"}


def test_identity_kinds_cross_check_historical_snapshot_without_promoting_it():
    baseline = json.loads((ROOT / "inventories/baselines/duckdb-1.5.5.json").read_text())
    historical = {}
    for row in baseline["functions"]:
        historical.setdefault(row["name"].lower(), set()).add(row["kind"])
    for identity in load_default_identities():
        name, kind = identity["name"], identity["type"]
        if kind == "window":
            discrepancy = next(group for group in load_default_mapping()["reporting_discrepancies"]
                               if name in group["names"])
            assert discrepancy["reported_type"] in historical[name]
            assert discrepancy["type"] == kind
            continue  # Explicit source-backed discrepancy, not an executable aggregate registration.
        if kind == "scalar" and name in {"unnest", "round_even", "roundbankers"}:
            continue  # Explicit separate source evidence, not present in the 1.5 catalog.
        if name in historical:
            assert kind in historical[name], identity
    # Source-only extension coverage is intentional, not silently discarded for lack of rows.
    absent = {row["name"] for row in load_default_identities()} - historical.keys()
    assert {"quack_uri_parser", "st_rotate", "parse_delta_filter_logline", "iceberg_bucket"} <= absent


@pytest.mark.parametrize("mutation", [
    "missing", "unknown-kind", "missing-kind", "wildcard-catalog", "wildcard-schema", "nested-schema",
    "duplicate", "excluded-grant", "unknown-name", "unknown-evidence", "wrong-owner", "unreviewed-source",
])
def test_default_mapping_rejects_incomplete_or_conflicting_provenance(tmp_path, mutation):
    shutil.copytree(ROOT / "inventories", tmp_path / "inventories")
    path = tmp_path / "inventories/default_identities.json"
    mapping = json.loads(path.read_text())
    group = mapping["grants"][0]
    if mutation == "missing":
        mapping["grants"].pop(0)
    elif mutation == "unknown-kind":
        group["type"] = "*"
    elif mutation == "missing-kind":
        del group["type"]
    elif mutation == "wildcard-catalog":
        group["catalog"] = "*"
    elif mutation == "wildcard-schema":
        group["schema_path"] = ["*"]
    elif mutation == "nested-schema":
        group["schema_path"] = ["main", "child"]
    elif mutation == "duplicate":
        mapping["grants"].append(copy.deepcopy(group))
    elif mutation == "excluded-grant":
        mapping["exclusions"].append({"evidence": group["evidence"], "names": group["names"], "reason": "conflict"})
    elif mutation == "unknown-name":
        group["names"] = ["not_reviewed"]
    elif mutation == "unknown-evidence":
        group["evidence"] = "runtime-discovery"
    elif mutation == "wrong-owner":
        group["evidence"] = "json"
    elif mutation == "unreviewed-source":
        mapping["evidence"][group["evidence"]]["sources"] = ["https://github.com/duckdb/duckdb/tree/main/src"]
    path.write_text(json.dumps(mapping))
    with pytest.raises(ValueError):
        load_default_identities(tmp_path)


def test_identity_schema_matches_reference():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "inventories/default_identities.schema.json").read_text())
    mapping = load_default_mapping()
    documents = [mapping]
    for field, value in [("type", "unknown"), ("catalog", "*"), ("schema_path", []), ("names", [None]),
                         ("names", []), ("extra", True)]:
        document = copy.deepcopy(mapping)
        document["grants"][0][field] = value
        documents.append(document)
    reference = jsonschema.Draft202012Validator(schema)
    for document in documents:
        expected = reference.is_valid(document)
        try:
            schema_check.validate(schema, document)
            actual = True
        except schema_check.ValidationError:
            actual = False
        assert actual == expected


def test_synthetic_window_labels_never_grant_or_hide_aggregate_collisions():
    mapping = load_default_mapping()
    names = mapping["reporting_discrepancies"][0]["names"]
    assert names == ["cume_dist", "dense_rank", "fill", "first_value", "lag", "last_value", "lead",
                     "nth_value", "ntile", "percent_rank", "rank", "rank_dense", "row_number"]
    defaults = load_default_identities()
    for name in names:
        assert {row["type"] for row in defaults if row["name"] == name} == {"window"}
    baseline = json.loads((ROOT / "inventories/baselines/duckdb-1.5.5.json").read_text())
    before = copy.deepcopy(baseline)
    report = reporting_discrepancies(baseline, mapping)
    assert report[0]["names"] == names and baseline == before
    candidate = {"duckdb_version": "v1.5.5", "functions": [
        {"catalog": "system", "schema_path": ["main"], "name": name, "kind": "aggregate"} for name in names]}
    assert len(qualified_drift(baseline, candidate, defaults)["default_names_at_ungranted_identities"]) == 13
    assert reporting_discrepancies({**candidate, "duckdb_version": "v2.0.0"}, mapping) == []


def test_synthetic_aggregate_grant_conflicts_with_registration_evidence(tmp_path):
    shutil.copytree(ROOT / "inventories", tmp_path / "inventories")
    path = tmp_path / "inventories/default_identities.json"
    mapping = json.loads(path.read_text())
    window = next(group for group in mapping["grants"] if group["type"] == "window")
    mapping["grants"].append({**window, "type": "aggregate"})
    path.write_text(json.dumps(mapping))
    with pytest.raises(ValueError, match="conflicting reporting discrepancy"):
        load_default_identities(tmp_path)


def test_default_identity_generation_is_dependency_free():
    code = "from inventory import load_default_identities; import json; print(json.dumps(load_default_identities()))"
    result = subprocess.check_output([sys.executable, "-S", "-c", code], cwd=ROOT / "scripts", text=True)
    assert json.loads(result) == load_default_identities()
    assert '"defaults":[{"catalog":"system"' in header("inventory", {"defaults": json.loads(result)})


def test_qualified_drift_distinguishes_kind_catalog_and_full_schema_path():
    def snapshot(catalog, path, kind):
        return {"duckdb_version": "v2", "loaded_extensions": [], "functions": [
            {"catalog": catalog, "schema_path": path, "name": "abs", "kind": kind}]}
    baseline = snapshot("system", ["main"], "scalar")
    for candidate in [snapshot("memory", ["main"], "scalar"), snapshot("system", ["a", "main"], "scalar"),
                      snapshot("system", ["main"], "macro")]:
        report = qualified_drift(baseline, candidate, load_default_identities())
        assert len(report["added"]) == len(report["removed"]) == 1
        assert report["default_names_at_ungranted_identities"] == report["added"]
    legacy = copy.deepcopy(baseline)
    del legacy["functions"][0]["catalog"]
    del legacy["functions"][0]["schema_path"]
    report = qualified_drift(legacy, baseline, load_default_identities())
    assert not report["baseline_qualified"] and report["added"] is None and report["removed"] is None
    assert compare(legacy, baseline)["changed"] == []
    modified = copy.deepcopy(baseline)
    modified["functions"][0]["returns"] = "BIGINT"
    assert qualified_drift(baseline, modified, load_default_identities())["changed"] == [
        {"catalog": "system", "schema_path": ["main"], "name": "abs", "type": "scalar"}]


def test_capture_preserves_literal_dots_and_kind():
    import duckdb
    with duckdb.connect() as db:
        db.execute('CREATE SCHEMA "a.b"; CREATE MACRO "a.b".identity_probe(x) AS x')
        rows = [row for row in capture_functions(db) if row["name"] == "identity_probe"]
    assert len(rows) == 1
    assert rows[0]["catalog"] == "memory" and rows[0]["schema_path"] == ["a.b"]
    assert rows[0]["kind"] == "macro"


def test_capture_disambiguates_nested_sibling_schemas():
    import duckdb
    if int(duckdb.__version__.split(".")[0]) < 2:
        pytest.skip("nested schemas require DuckDB 2")
    with duckdb.connect() as db:
        db.execute("CREATE SCHEMA a; CREATE SCHEMA a.b; CREATE SCHEMA z; CREATE SCHEMA z.b; "
                   "CREATE MACRO a.b.identity_probe(x) AS x; CREATE MACRO z.b.identity_probe(x) AS x + 1")
        rows = [row for row in capture_functions(db) if row["name"] == "identity_probe"]
    assert {tuple(row["schema_path"]) for row in rows} == {("a", "b"), ("z", "b")}
    assert all(row["kind"] == "macro" and row["catalog"] == "memory" for row in rows)
