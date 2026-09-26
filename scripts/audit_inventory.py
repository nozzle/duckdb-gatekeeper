"""Capture/diff runtime signatures; never classify or install extensions automatically."""
import argparse
import json
from pathlib import Path

from inventory import ROOT, load, check_sources, load_default_identities, load_default_mapping, identity_key
from versions import BASELINE_FILENAME
from inventory_capture import snapshot, reconstruct_collection, union_snapshot, digest, require


def schema_paths(db):
    """Reconstruct nested schema paths by OID, never by splitting SQL identifiers on dots."""
    cursor = db.execute("SELECT * FROM duckdb_schemas()")
    columns = [column[0] for column in cursor.description]
    schemas = [dict(zip(columns, row)) for row in cursor.fetchall()]
    by_oid = {(str(row["database_oid"]), row["oid"]): row for row in schemas}

    def path(row, seen=()):
        key = str(row["database_oid"]), row["oid"]
        if key in seen:
            raise ValueError("cycle in runtime schema ancestry")
        parent = row.get("parent_schema_oid")
        if parent is None:
            return [row["schema_name"]]
        parent_row = by_oid.get((key[0], parent))
        if parent_row is None:
            raise ValueError("missing runtime parent schema")
        return path(parent_row, (*seen, key)) + [row["schema_name"]]

    return [(row, path(row)) for row in schemas]


def capture_functions(db):
    schemas = schema_paths(db)
    # duckdb_functions exposes only the innermost schema name, even on 2.0. Dependencies
    # identify the containing schema when two nested schemas have the same leaf name.
    dependencies = {}
    if any(len(path) > 1 for _, path in schemas):
        for schema_oid, function_oid in db.execute("SELECT objid, refobjid FROM duckdb_dependencies()").fetchall():
            dependencies.setdefault(function_oid, set()).add(schema_oid)
    rows = db.execute("""SELECT function_name, function_type, parameter_types,
        return_type, varargs, has_side_effects, macro_definition, parameters,
        database_name, database_oid, schema_name, function_oid
        FROM duckdb_functions()
        WHERE function_type IN ('scalar','aggregate','table','macro','table_macro','window')
        ORDER BY ALL""").fetchall()
    signatures = []
    for row in rows:
        entry = dict(zip(["name", "kind", "parameters", "returns", "varargs", "side_effects", "macro",
                          "parameter_names", "catalog", "database_oid", "schema_name", "function_oid"], row))
        candidates = [(schema, path) for schema, path in schemas
                      if str(schema["database_oid"]) == str(entry["database_oid"])
                      and schema["schema_name"] == entry["schema_name"]]
        if len(candidates) > 1:
            candidates = [(schema, path) for schema, path in candidates
                          if schema["oid"] in dependencies.get(entry["function_oid"], set())]
        if len(candidates) != 1:
            raise ValueError("cannot resolve full runtime schema path for " + repr(entry))
        entry["schema_path"] = candidates[0][1]
        for field in ["database_oid", "schema_name", "function_oid"]:
            entry.pop(field)
        if entry["kind"] == "table":
            pairs = list(zip(entry.pop("parameter_names"), entry["parameters"]))
            # Positional colN arguments precede an unordered named-argument map.
            positional = 0
            while positional < len(pairs) and pairs[positional][0] == f"col{positional}":
                positional += 1
            entry["parameters"] = [typ for _, typ in pairs[:positional]]
            entry["named_parameters"] = dict(sorted(pairs[positional:]))
        else:
            entry.pop("parameter_names")
        signatures.append(entry)
    return sorted(signatures, key=lambda entry: json.dumps(entry, sort_keys=True))


def capture(extension_paths=()):
    # Imported here: the comparison path (--candidate) needs neither duckdb nor the artifact module.
    import duckdb
    from artifact import load as load_extension

    # Naming a local file is the trust decision; the engine's signature check guards repository downloads,
    # which this tool never performs. Without paths the setting is left alone and nothing is loaded.
    config = {"allow_unsigned_extensions": "true"} if extension_paths else {}
    with duckdb.connect(config=config) as db:
        before = db.execute("SELECT extension_name, extension_version FROM duckdb_extensions() WHERE loaded ORDER BY 1").fetchall()
        for path in extension_paths:
            load_extension(db, path)
        signatures = capture_functions(db)
        return {"duckdb_version": db.execute("SELECT version()").fetchone()[0],
                "loaded_extensions": db.execute("SELECT extension_name, extension_version FROM duckdb_extensions() WHERE loaded ORDER BY 1").fetchall(),
                "initial_extensions": before, "functions": signatures}


def compare(baseline, candidate):
    baseline, candidate = snapshot(baseline), snapshot(candidate)
    def grouped(snapshot):
        result = {}
        for entry in snapshot["functions"]:
            # Keep the historical name/signature report comparable without inventing
            # qualifications for the old, unqualified baseline.
            signature = {k: v for k, v in entry.items() if k not in {"catalog", "schema_path"}}
            result.setdefault(entry["name"], set()).add(json.dumps(signature, sort_keys=True))
        return result

    old, new = grouped(baseline), grouped(candidate)
    return {"added": sorted(new.keys() - old.keys()), "removed": sorted(old.keys() - new.keys()),
            "changed": sorted(name for name in old.keys() & new.keys() if old[name] != new[name]),
            "version_changed": baseline["duckdb_version"] != candidate["duckdb_version"],
            "extensions_changed": json.dumps(baseline["loaded_extensions"]) != json.dumps(candidate["loaded_extensions"])}


def qualified_identities(snapshot):
    return {identity_key({"catalog": row["catalog"].lower(), "schema_path": [p.lower() for p in row["schema_path"]],
                          "name": row["name"].lower(), "type": row["kind"]})
            for row in snapshot["functions"] if "catalog" in row and "schema_path" in row and "kind" in row}


def identities_json(keys):
    return [{"catalog": c, "schema_path": list(s), "name": n, "type": t} for c, s, n, t in sorted(keys)]


def qualified_drift(baseline, candidate, defaults):
    old, new = qualified_identities(baseline), qualified_identities(candidate)
    baseline_complete = all("catalog" in row and "schema_path" in row and "kind" in row
                            for row in baseline["functions"])
    candidate_complete = all("catalog" in row and "schema_path" in row and "kind" in row
                             for row in candidate["functions"])
    grants = {identity_key(identity) for identity in defaults}
    names = {identity["name"] for identity in defaults}

    def signatures(snapshot):
        result = {}
        for row in snapshot["functions"]:
            key = next(iter(qualified_identities({"functions": [row]})))
            signature = {k: v for k, v in row.items() if k not in {"catalog", "schema_path", "name", "kind"}}
            result.setdefault(key, set()).add(json.dumps(signature, sort_keys=True))
        return result

    changed = None
    if baseline_complete and candidate_complete:
        old_signatures, new_signatures = signatures(baseline), signatures(candidate)
        changed = identities_json({key for key in old & new if old_signatures[key] != new_signatures[key]})
    return {"baseline_qualified": baseline_complete, "candidate_qualified": candidate_complete,
            "added": identities_json(new - old) if baseline_complete and candidate_complete else None,
            "removed": identities_json(old - new) if baseline_complete and candidate_complete else None,
            "changed": changed,
            "default_names_at_ungranted_identities": identities_json({key for key in new - grants if key[2] in names}),
            "defaults_not_observed": identities_json(grants - new) if candidate_complete else None}


def coverage(snapshot, entries):
    known = set(n for entry in entries.values() for group in ["compute", "elevated", "unreviewed"] for n in entry.get(group, []))
    names = {row["name"].lower() for row in snapshot["functions"]}
    return {"unclassified_runtime_names": sorted(names - known)}


def reporting_discrepancies(snapshot, mapping):
    """Explain historical synthetic labels without relabeling rows or hiding collisions.

    Old snapshots have no OIDs/qualification: matching a name and kind is an explanation
    of the source's reporting convention, never proof that an arbitrary row is intrinsic.
    Qualified aggregate rows still appear in the ungranted-identity report.
    """
    result = []
    for group in mapping["reporting_discrepancies"]:
        if snapshot.get("duckdb_version", snapshot.get("engine", {}).get("library_version")) != group["duckdb_version"]:
            continue
        observed = {row["name"].lower() for row in snapshot["functions"]
                    if row.get("kind") == group["reported_type"]
                    and row.get("catalog", group["catalog"]).lower() == group["catalog"]
                    and row.get("schema_path", group["schema_path"]) == group["schema_path"]}
        names = sorted(observed & set(group["names"]))
        if names:
            result.append({**group, "names": names,
                           "note": "Synthetic reporting convention; rows unchanged. This is not an aggregate grant "
                                   "or proof of row provenance. Qualified aggregate collisions remain ungranted."})
    return result


def identity_coverage(candidate, defaults, entries, mapping):
    """Exact sets, not inferred permissions. Missing source-backed kinds remain visible."""
    observed = qualified_identities(candidate)
    grants = {identity_key(row) for row in defaults}
    names = {row[2] for row in grants}
    return {"observed_default_identities": identities_json(grants & observed),
            "defaults_not_observed": identities_json(grants - observed),
            "default_names_at_ungranted_identities": identities_json({k for k in observed - grants if k[2] in names}),
            **coverage(candidate, entries), "reporting_discrepancies": reporting_discrepancies(candidate, mapping)}


def collection_report(path, root=ROOT):
    """Recompute policy coverage from verified stages and the current source-backed map."""
    base, outcomes = reconstruct_collection(path)
    entries, _ = load(root)
    defaults, mapping = load_default_identities(root), load_default_mapping(root)
    per_extension = {}
    snapshots = [base]
    for name, outcome in outcomes.items():
        metadata, stages = outcome["metadata"], outcome["snapshots"]
        item = {"status": metadata["status"], "load_names": metadata["load_names"],
                "stage_hashes": [stage["functions_sha256"] for stage in metadata.get("stages", [])]}
        per_extension[name] = item
        if metadata["status"] != "ok":
            continue
        before, target = stages[-2:]
        snapshots.append(target)
        source_names = set(entries.get(name, {}).get("compute", []))
        source_defaults = [row for row in defaults if row["name"] in source_names]
        observed_before = qualified_identities(before)
        target_delta = qualified_drift(before, target, defaults)
        source_coverage = identity_coverage(target, source_defaults, entries, mapping)
        item.update({"dependencies_loaded": metadata["dependencies_loaded"],
                     "final_signature_count": len(target["functions"]),
                     "target_identities": {key: target_delta[key] for key in ("added", "removed", "changed")},
                     "source_default_identities_present_before_target": identities_json(
                         {identity_key(row) for row in source_defaults} & observed_before),
                     "source_default_coverage": {key: source_coverage[key] for key in (
                         "observed_default_identities", "defaults_not_observed", "default_names_at_ungranted_identities")},
                     "target_default_names_at_ungranted_identities": [row for row in target_delta["added"]
                         if row in target_delta["default_names_at_ungranted_identities"]],
                     "unclassified_target_added_names": sorted({row["name"] for row in target_delta["added"]}
                         & set(coverage(target, entries)["unclassified_runtime_names"]))})
    union = union_snapshot(snapshots)
    return {"report_schema": "gatekeeper-qualified-collection-audit-v1",
            "scope": "Union of base and successful independent final setups; not a combined live catalog.",
            "engine": base["engine"], "base_sha256": digest(json.loads(
                ((Path(path).parent if Path(path).name == "collection.json" else Path(path)) / "base.json").read_text())),
            "policy_sha256": digest({"entries": entries, "mapping": mapping}),
            "compiled_defaults": len(defaults), "union_signatures": len(union["functions"]),
            "union_qualified_identities": len(qualified_identities(union)),
            **identity_coverage(union, defaults, entries, mapping), "per_extension": per_extension}


def verify_collection_report(path, root=ROOT, report_path=None):
    """Check every field of the reproducible report, including equal-count substitutions."""
    path = Path(path)
    if path.name == "collection.json":
        path = path.parent
    expected = collection_report(path, root)
    actual = json.loads(Path(report_path or path / "qualified-report.json").read_text())
    require(actual == expected, "Qualified collection report differs from reconstructed captures/current policy")
    return expected


def verify_historical_report(path, report):
    """Recheck aggregate claims in the two committed historical report formats.

    Exploratory origin annotations and historical name comparisons remain evidence;
    the qualified report is the reproducible replacement for per-stage policy checks.
    """
    old = json.loads((Path(path) / "report.json").read_text())
    if "qualified_source_mapping" in old:
        for field in ("defaults_not_observed", "default_names_at_ungranted_identities"):
            require(old["qualified_source_mapping"][field] == report[field], f"Historical report {field} mismatch")
        require(old["reporting_discrepancies"] == report["reporting_discrepancies"], "Historical reporting discrepancy mismatch")
        require(old["unclassified_added_names"] == report["unclassified_runtime_names"], "Historical unclassified names mismatch")
    else:
        for field in ("compiled_defaults", "union_signatures", "union_qualified_identities", "defaults_not_observed",
                      "default_names_at_ungranted_identities", "unclassified_runtime_names"):
            require(old[field] == report[field], f"Historical report {field} mismatch")
        require(old["observed_default_identities"] == len(report["observed_default_identities"]),
                "Historical observed default count mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, help="write a candidate snapshot, without approving it")
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--candidate", type=Path, help="compare a full historical or collector base snapshot")
    inputs.add_argument("--collection", type=Path, help="audit a staged collection directory offline")
    parser.add_argument("--extension", help="with --collection, compare one successful reconstructed target")
    parser.add_argument("--verify-report", type=Path, help="with --collection, verify the complete qualified report")
    parser.add_argument("--write-report", type=Path, help="with --collection, write the reproducible qualified report")
    parser.add_argument("--baseline", type=Path, default=ROOT / "inventories/baselines" / BASELINE_FILENAME)
    parser.add_argument("--load-extension", type=Path, action="append", default=[], help="local extension file to LOAD during capture, signed or not (repeatable)")
    parser.add_argument("--check-sources", action="store_true",
                        help="verify provenance against a checkout of the historical review engine")
    parser.add_argument("--source-checkout", type=Path,
                        help="historical DuckDB checkout for --check-sources (default: local submodule)")
    parser.add_argument("--strict", action="store_true", help="fail on runtime drift (default: report only)")
    args = parser.parse_args()
    if (args.extension or args.verify_report or args.write_report) and not args.collection:
        parser.error("--extension/--verify-report/--write-report require --collection")
    if args.collection and (args.capture or args.load_extension):
        parser.error("--collection is offline and cannot be combined with capture/loading")
    if args.extension and (args.verify_report or args.write_report):
        parser.error("report verification/writing applies to the whole collection")
    entries, names = load()
    defaults = load_default_identities()
    mapping = load_default_mapping()
    if args.check_sources:
        check_sources(entries, duckdb_source=args.source_checkout)
    if args.collection:
        if not args.extension:
            report = (verify_collection_report(args.collection, report_path=args.verify_report)
                      if args.verify_report else collection_report(args.collection))
            if args.write_report:
                args.write_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            else:
                print(json.dumps(report, indent=2, sort_keys=True))
            if args.strict and (report["defaults_not_observed"] or report["unclassified_runtime_names"]
                               or report["default_names_at_ungranted_identities"]
                               or any(item["status"] != "ok" for item in report["per_extension"].values())):
                raise SystemExit("Runtime collection has coverage drift or incomplete outcomes")
            return
        _, outcomes = reconstruct_collection(args.collection)
        if args.extension not in outcomes or outcomes[args.extension]["metadata"]["status"] != "ok":
            parser.error("Requested extension has no successful target snapshot")
        candidate = outcomes[args.extension]["snapshots"][-1]
    else:
        candidate = snapshot(json.loads(args.candidate.read_text())) if args.candidate else capture(args.load_extension)
    if args.capture:
        args.capture.parent.mkdir(parents=True, exist_ok=True)
        args.capture.write_text(json.dumps(candidate, indent=2) + "\n")
        print(f"Candidate snapshot written to {args.capture}; review before accepting as baseline")
        return
    baseline = json.loads(args.baseline.read_text())
    delta = compare(baseline, candidate)
    qualified = qualified_drift(baseline, candidate, defaults)
    report = {**delta, **coverage(candidate, entries), "compiled_default_count": len(defaults),
              "reviewed_compute_name_count": len(names),
              "compiled_default_name_count": len({identity["name"] for identity in defaults}),
              "default_exclusions": mapping["exclusions"], "qualified_drift": qualified,
              "reporting_discrepancies": {"baseline": reporting_discrepancies(baseline, mapping),
                                          "candidate": reporting_discrepancies(candidate, mapping)},
              "default_namespace": {"catalog": "system", "schema_path": ["main"]}}
    print(json.dumps(report, indent=2))
    if args.strict and (any(delta.values()) or report["unclassified_runtime_names"]
                        or qualified["added"] or qualified["removed"] or qualified["changed"]
                        or qualified["default_names_at_ungranted_identities"]):
        raise SystemExit("Runtime inventory differs from the historical baseline")


if __name__ == "__main__":
    main()
