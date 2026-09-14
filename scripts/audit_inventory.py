"""Capture/diff runtime signatures; never classify or install extensions automatically."""
import argparse
import json
from pathlib import Path
import sys

from inventory import ROOT, load, check_sources
from versions import BASELINE_FILENAME


def capture(extension_paths=()):
    import duckdb

    with duckdb.connect() as db:
        before = db.execute("SELECT extension_name, extension_version FROM duckdb_extensions() WHERE loaded ORDER BY 1").fetchall()
        for path in extension_paths:
            db.execute("LOAD '" + str(Path(path).resolve()).replace("'", "''") + "'")
        rows = db.execute("""SELECT function_name, function_type, parameter_types,
            return_type, varargs, has_side_effects, macro_definition
            , parameters
            FROM duckdb_functions()
            WHERE function_type IN ('scalar','aggregate','table','macro','table_macro')
            ORDER BY ALL""").fetchall()
        signatures = []
        for row in rows:
            entry = dict(zip(["name", "kind", "parameters", "returns", "varargs", "side_effects", "macro", "parameter_names"], row))
            if entry["kind"] == "table":
                pairs = list(zip(entry.pop("parameter_names"), entry["parameters"]))
                # DuckDB emits positional colN arguments first, then an unordered named-argument map.
                positional = 0
                while positional < len(pairs) and pairs[positional][0] == f"col{positional}":
                    positional += 1
                entry["parameters"] = [typ for _, typ in pairs[:positional]]
                entry["named_parameters"] = dict(sorted(pairs[positional:]))
            else:
                entry.pop("parameter_names")
            signatures.append(entry)
        return {"duckdb_version": db.execute("SELECT version()").fetchone()[0],
                "loaded_extensions": db.execute("SELECT extension_name, extension_version FROM duckdb_extensions() WHERE loaded ORDER BY 1").fetchall(),
                "initial_extensions": before, "functions": signatures}


def compare(baseline, candidate):
    def grouped(snapshot):
        result = {}
        for entry in snapshot["functions"]:
            result.setdefault(entry["name"], set()).add(json.dumps(entry, sort_keys=True))
        return result

    old, new = grouped(baseline), grouped(candidate)
    return {"added": sorted(new.keys() - old.keys()), "removed": sorted(old.keys() - new.keys()),
            "changed": sorted(name for name in old.keys() & new.keys() if old[name] != new[name]),
            "version_changed": baseline["duckdb_version"] != candidate["duckdb_version"],
            "extensions_changed": json.dumps(baseline["loaded_extensions"]) != json.dumps(candidate["loaded_extensions"])}


def coverage(snapshot, entries):
    known = set(n for entry in entries.values() for group in ["compute", "elevated", "unreviewed"] for n in entry.get(group, []))
    names = {row["name"].lower() for row in snapshot["functions"]}
    return {"unclassified_runtime_names": sorted(names - known)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, help="write a candidate snapshot, without approving it")
    parser.add_argument("--candidate", type=Path, help="compare a previously captured snapshot")
    parser.add_argument("--baseline", type=Path, default=ROOT / "inventories/baselines" / BASELINE_FILENAME)
    parser.add_argument("--load-extension", type=Path, action="append", default=[], help="explicit trusted local signed extension to load during capture")
    parser.add_argument("--check-sources", action="store_true",
                        help="verify provenance against a checkout of the historical review engine")
    parser.add_argument("--source-checkout", type=Path,
                        help="historical DuckDB checkout for --check-sources (default: local submodule)")
    parser.add_argument("--strict", action="store_true", help="fail on runtime drift (default: report only)")
    args = parser.parse_args()
    entries, defaults = load()
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
    report = {**delta, **coverage(candidate, entries), "compiled_default_count": len(defaults)}
    print(json.dumps(report, indent=2))
    if args.strict and (any(delta.values()) or report["unclassified_runtime_names"]):
        raise SystemExit("Runtime inventory differs from the historical baseline")


if __name__ == "__main__":
    main()
