"""Capture/diff runtime signatures; never classify or install extensions automatically."""
import argparse
import json
from pathlib import Path

from inventory import ROOT, load, check_sources, load_default_identities, load_default_mapping, identity_key
from versions import BASELINE_FILENAME


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, help="write a candidate snapshot, without approving it")
    parser.add_argument("--candidate", type=Path, help="compare a previously captured snapshot")
    parser.add_argument("--baseline", type=Path, default=ROOT / "inventories/baselines" / BASELINE_FILENAME)
    parser.add_argument("--load-extension", type=Path, action="append", default=[], help="local extension file to LOAD during capture, signed or not (repeatable)")
    parser.add_argument("--check-sources", action="store_true",
                        help="verify provenance against a checkout of the historical review engine")
    parser.add_argument("--source-checkout", type=Path,
                        help="historical DuckDB checkout for --check-sources (default: local submodule)")
    parser.add_argument("--strict", action="store_true", help="fail on runtime drift (default: report only)")
    args = parser.parse_args()
    entries, names = load()
    defaults = load_default_identities()
    mapping = load_default_mapping()
    candidate = json.loads(args.candidate.read_text()) if args.candidate else capture(args.load_extension)
    if args.capture:
        args.capture.parent.mkdir(parents=True, exist_ok=True)
        args.capture.write_text(json.dumps(candidate, indent=2) + "\n")
        print(f"Candidate snapshot written to {args.capture}; review before accepting as baseline")
        return
    if args.check_sources:
        check_sources(entries, duckdb_source=args.source_checkout)
    baseline = json.loads(args.baseline.read_text())
    delta = compare(baseline, candidate)
    qualified = qualified_drift(baseline, candidate, defaults)
    report = {**delta, **coverage(candidate, entries), "compiled_default_count": len(defaults),
              "reviewed_compute_name_count": len(names),
              "compiled_default_name_count": len({identity["name"] for identity in defaults}),
              "default_exclusions": mapping["exclusions"], "qualified_drift": qualified,
              "default_namespace": {"catalog": "system", "schema_path": ["main"]}}
    print(json.dumps(report, indent=2))
    if args.strict and (any(delta.values()) or report["unclassified_runtime_names"]
                        or qualified["added"] or qualified["removed"] or qualified["changed"]
                        or qualified["default_names_at_ungranted_identities"]):
        raise SystemExit("Runtime inventory differs from the historical baseline")


if __name__ == "__main__":
    main()
