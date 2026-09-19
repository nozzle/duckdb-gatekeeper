"""Load a distributable Gatekeeper artifact into the pinned DuckDB Python package and exercise the checks
whose correctness depends on the host/loadable ABI boundary rather than on SQL semantics alone.

The sqllogictests run against a statically linked unittest binary, where the extension and the engine are one
image. A distributed loadable instead inspects bind data created by the host's copy of DuckDB (list lambda
bodies, list-aggregate serialization callbacks, replacement-scan callbacks). This script fails if any of
those paths silently degrade.

    python scripts/smoke_loadable.py path/to/gatekeeper.duckdb_extension
"""
from pathlib import Path
import sys
import tempfile

import duckdb

from artifact import connect


def validate(db, sql, options=None):
    arguments, values = ["?"], [sql]
    for key, value in (options or {}).items():
        arguments.append(key + " := ?")
        values.append(value)
    result = db.execute("SELECT * FROM gatekeeper_validate(" + ", ".join(arguments) + ")", values)
    return dict(zip((column[0] for column in result.description), result.fetchone()))


def expect(condition, message):
    if not condition:
        raise SystemExit("::error::" + message)


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    artifact = Path(argv[1]).resolve()
    db = connect(artifact, autoload_known_extensions=False, autoinstall_known_extensions=False)
    print("host", db.execute("PRAGMA version").fetchone(),
          "extension", db.execute("SELECT extension_version FROM duckdb_extensions() WHERE extension_name = 'gatekeeper'").fetchone())

    db.execute("CREATE TABLE t(x INTEGER, s VARCHAR)")
    db.execute("CREATE VIEW lambda_view AS SELECT list_transform(['a'], lambda v: v COLLATE nocase = 'A') AS l")
    db.execute("CREATE VIEW nested_lambda AS SELECT list_transform([['a']], lambda xs: list_filter(xs, lambda v: v COLLATE nocase = 'A')) AS l")
    db.execute("CREATE VIEW dispatched AS SELECT list_aggregate([1, 2], 'sum') AS s")
    db.execute("CREATE VIEW unnested AS SELECT unnest([1, 2]) AS u")

    # Lambda bodies inside trusted definitions are reached through the host-created bind data: the collation's
    # lower is observed there and is the view's own, while the same lambda written by the caller is blockable.
    for view, expression in (("lambda_view", "list_transform(['a'], lambda v: v COLLATE nocase = 'A')"),
                             ("nested_lambda", "list_transform([['a']], lambda xs: list_filter(xs, lambda v: v COLLATE nocase = 'A'))")):
        result = validate(db, f"SELECT * FROM {view}")
        expect(result["allowed"] and any(f["name"] == "lower" for f in result["functions"]),
               f"{view}: lambda body implementation not observed: {result}")
        result = validate(db, f"SELECT * FROM {view}", {"blocked_functions": ["lower"]})
        expect(result["allowed"], f"{view}: block reached the view's own lambda body: {result}")
        result = validate(db, f"SELECT {expression}", {"blocked_functions": ["lower"]})
        expect(result["code"] == "forbidden" and result["violations"][0]["function_name"] == "lower",
               f"{view}: block did not reach the caller's lambda body: {result}")

    # The dispatched aggregate is recovered through the serialization callback of the host's function.
    result = validate(db, "SELECT * FROM dispatched")
    expect(result["allowed"] and any(f["name"] == "sum" and f["type"] == "aggregate" for f in result["functions"]),
           f"dispatched aggregate not observed: {result}")
    result = validate(db, "SELECT * FROM dispatched", {"blocked_functions": ["sum"]})
    expect(result["allowed"], f"block reached the view's own dispatched aggregate: {result}")
    db.execute("CALL gatekeeper_configure(allowed_functions := ['list_aggregate'])")
    result = validate(db, "SELECT list_aggregate([1, 2], 'sum')", {"blocked_functions": ["sum"]})
    expect(result["code"] == "forbidden" and result["violations"][0]["function_name"] == "sum",
           f"block did not reach the caller's dispatched aggregate: {result}")
    db.execute("CALL gatekeeper_configure(use_default_functions := false, allowed_functions := ['list_aggregate', 'list_value'])")
    result = validate(db, "SELECT list_aggregate([1, 2], 'sum')")
    expect(result["code"] == "forbidden" and result["violations"][0]["function_name"] == "sum",
           f"caller-written dispatch target escaped the allowlist: {result}")
    db.execute("RESET gatekeeper_policy")

    result = validate(db, "SELECT * FROM unnested", {"blocked_functions": ["unnest"]})
    expect(result["allowed"] and any(f["name"] == "unnest" for f in result["functions"]),
           f"block reached unnest inside a view, or unnest not observed: {result}")
    result = validate(db, "SELECT unnest([1, 2])", {"blocked_functions": ["unnest"]})
    expect(result["code"] == "forbidden", f"block did not reach the caller's unnest: {result}")

    # Replacement scans are decided in Gatekeeper's callback before the host's reader binds.
    with tempfile.TemporaryDirectory() as directory:
        path = str(Path(directory) / "data.parquet").replace("'", "''")
        db.execute(f"COPY (SELECT 1 AS x) TO '{path}'")
        result = validate(db, f"SELECT * FROM '{path}'")
        expect(result["code"] == "forbidden" and result["violations"][0]["function_name"] == "read_parquet",
               f"replacement scan admitted without a reader grant: {result}")
        db.execute("CALL gatekeeper_configure(allowed_functions := ['read_parquet'])")
        result = validate(db, f"SELECT * FROM '{path}'")
        expect(result["allowed"] and result["objects"][0]["type"] == "replacement",
               f"granted replacement scan not recorded: {result}")
        db.execute("RESET gatekeeper_policy")

    # The policy setting round-trips through the host's DBConfig and prepared executions re-read it.
    db.execute("PREPARE p AS SELECT allowed FROM gatekeeper_validate('SELECT md5(s) FROM t')")
    expect(db.execute("EXECUTE p").fetchone() == (True,), "prepared validation did not allow md5")
    db.execute("CALL gatekeeper_configure(blocked_functions := ['md5'])")
    expect(db.execute("EXECUTE p").fetchone() == (False,), "prepared validation did not re-read the policy")
    expect(db.execute("SELECT current_setting('gatekeeper_policy').blocked_functions").fetchone() == (["md5"],),
           "policy readback disagrees with the configured value")
    db.execute("SET lock_configuration = true")
    try:
        db.execute("CALL gatekeeper_configure()")
    except duckdb.Error as error:
        expect("locked" in str(error).lower(), f"unexpected lock error: {error}")
    else:
        raise SystemExit("::error::gatekeeper_configure ignored lock_configuration")
    print(artifact.name + ": loadable smoke checks passed")


if __name__ == "__main__":
    main(sys.argv)
