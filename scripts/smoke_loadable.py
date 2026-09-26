"""Load a distributable Gatekeeper artifact into the pinned DuckDB Python package and exercise the checks
whose correctness depends on the host/loadable ABI boundary rather than on SQL semantics alone.

The sqllogictests run against a statically linked unittest binary, where the extension and the engine are one
image. A distributed loadable instead inspects bind data created by the host's copy of DuckDB (list lambda
bodies, list-aggregate serialization callbacks, replacement-scan callbacks), hooks the host's query lifecycle
(QueryBegin, the planner's post-bind callback, the client-context state an enforced connection lives in), and
writes to the host's log manager. This script fails if any of those paths silently degrade. On the platforms
where the Python suite does not run against the artifact, this is the only execution of enforcement, log-only
mode, and the audit log against the shipped binary.

The same checks exist once more as plain SQL in scripts/smoke/ (loadable.sql, enforced.sql), the form the
hosts without a Python package run: the DuckDB CLI for the musl targets (scripts/smoke_cli.sh) and the CRAN
package for MinGW (scripts/smoke_loadable.R). This script runs those files too, so the portable form is
exercised on every Python-capable target and test/test_smoke_sql.py keeps it current on the local build.

    python scripts/smoke_loadable.py path/to/gatekeeper.duckdb_extension
"""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import NamedTuple, Optional

import duckdb

from artifact import connect

SMOKE_DIR = Path(__file__).resolve().parent / "smoke"
# One per paragraph in enforced.sql: the connection, and the text a statement that must fail has to raise.
DIRECTIVE = re.compile(r"^--\s*@(host|agent)(?:\s+expect error:\s*(.+?))?\s*$")


class Statement(NamedTuple):
    connection: str  # "host" or "agent"
    sql: str
    error: Optional[str]  # substring the statement must fail with; None when it must succeed
    line: int  # first line of the paragraph, for messages


def statements(path):
    """The paragraphs of a smoke SQL file: blank-line separated, comment lines removed, directive parsed.

    A paragraph without a directive runs on the host connection and must succeed, which is every paragraph of
    loadable.sql. The trailing semicolon is dropped so a logged statement equals the text the file shows."""
    result, paragraph, first_line = [], [], None
    for number, line in enumerate(Path(path).read_text().splitlines() + [""], start=1):
        if line.strip():
            if not paragraph:
                first_line = number
            paragraph.append(line)
            continue
        if not paragraph:
            continue
        connection, error, directives = "host", None, 0
        for comment in (l for l in paragraph if l.lstrip().startswith("--")):
            match = DIRECTIVE.match(comment.strip())
            if match:
                connection, error, directives = match.group(1), match.group(2), directives + 1
        if directives > 1:
            raise ValueError(f"{Path(path).name}:{first_line}: {directives} directives in one paragraph")
        sql = "\n".join(l for l in paragraph if not l.lstrip().startswith("--")).strip().rstrip(";").strip()
        if sql:
            result.append(Statement(connection, sql, error, first_line))
        paragraph = []
    return result


def run(path, connections):
    """Execute a smoke SQL file. ``connections`` maps ``host`` (and ``agent`` for enforced.sql) to DuckDB
    connections on one database. Exits with the failing statement's message. Run it from a scratch directory:
    loadable.sql writes gatekeeper_smoke.parquet relative to the working directory."""
    name = Path(path).name
    for statement in statements(path):
        try:
            connections[statement.connection].execute(statement.sql).fetchall()
        except duckdb.Error as error:
            if statement.error is None:
                raise SystemExit(f"::error::{name}:{statement.line}: {error}")
            expect(statement.error in str(error), f"{name}:{statement.line}: failed with the wrong error: {error}")
        else:
            expect(statement.error is None, f"{name}:{statement.line}: succeeded, expected an error containing "
                                            f"{statement.error!r}")


@contextmanager
def scratch_directory():
    """A temporary working directory for the files a smoke run writes."""
    previous = os.getcwd()
    with tempfile.TemporaryDirectory() as directory:
        os.chdir(directory)
        try:
            yield Path(directory)
        finally:
            os.chdir(previous)


def run_sql_smoke(artifact):
    """Both portable files against fresh databases on ``artifact``, as the CLI and R drivers run them."""
    with scratch_directory():
        with connect(artifact, autoload_known_extensions=False, autoinstall_known_extensions=False) as host:
            run(SMOKE_DIR / "loadable.sql", {"host": host})
        with connect(artifact, autoload_known_extensions=False, autoinstall_known_extensions=False) as host:
            with host.cursor() as agent:
                run(SMOKE_DIR / "enforced.sql", {"host": host, "agent": agent})


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
        result = validate(db, f"SELECT * FROM {view}", {"blocked_functions": [{"schema_path":["*"],"name":"lower"}]})
        expect(result["allowed"], f"{view}: block reached the view's own lambda body: {result}")
        result = validate(db, f"SELECT {expression}", {"blocked_functions": [{"schema_path":["*"],"name":"lower"}]})
        expect(result["code"] == "forbidden" and
               (result["violations"][0]["function_name"] == "lower" or result["violations"][0]["rule"] == "bind_time_expression"),
               f"{view}: block did not reach the caller's lambda body: {result}")

    # The dispatched aggregate is recovered through the serialization callback of the host's function.
    result = validate(db, "SELECT * FROM dispatched")
    expect(result["allowed"] and any(f["name"] == "sum" and f["type"] == "aggregate" for f in result["functions"]),
           f"dispatched aggregate not observed: {result}")
    result = validate(db, "SELECT * FROM dispatched", {"blocked_functions": [{"schema_path":["*"],"name":"sum"}]})
    expect(result["allowed"], f"block reached the view's own dispatched aggregate: {result}")
    db.execute("CALL gatekeeper_configure(allowed_functions := [{'catalog':'system','schema_path':['main'],'name':'list_aggregate'}])")
    result = validate(db, "SELECT list_aggregate([1, 2], 'sum')", {"blocked_functions": [{"schema_path":["*"],"name":"sum"}]})
    expect(result["code"] == "forbidden" and result["violations"][0]["function_name"] == "sum",
           f"block did not reach the caller's dispatched aggregate: {result}")
    db.execute("CALL gatekeeper_configure(use_default_functions := false, allowed_functions := [{'catalog':'system','schema_path':['main'],'name':'list_aggregate'}, {'catalog':'system','schema_path':['main'],'name':'list_value'}])")
    result = validate(db, "SELECT list_aggregate([1, 2], 'sum')")
    expect(result["code"] == "forbidden" and result["violations"][0]["function_name"] == "sum",
           f"caller-written dispatch target escaped the allowlist: {result}")
    db.execute("RESET gatekeeper_policy")

    result = validate(db, "SELECT * FROM unnested", {"blocked_functions": [{"schema_path":["*"],"name":"unnest"}]})
    expect(result["allowed"] and any(f["name"] == "unnest" for f in result["functions"]),
           f"block reached unnest inside a view, or unnest not observed: {result}")
    result = validate(db, "SELECT unnest([1, 2])", {"blocked_functions": [{"schema_path":["*"],"name":"unnest"}]})
    expect(result["code"] == "forbidden", f"block did not reach the caller's unnest: {result}")

    # Replacement scans are decided in Gatekeeper's callback before the host's reader binds.
    with tempfile.TemporaryDirectory() as directory:
        path = str(Path(directory) / "data.parquet").replace("'", "''")
        db.execute(f"COPY (SELECT 1 AS x) TO '{path}'")
        result = validate(db, f"SELECT * FROM '{path}'")
        expect(result["code"] == "forbidden" and result["violations"][0]["function_name"] == "read_parquet",
               f"replacement scan admitted without a reader grant: {result}")
        db.execute("CALL gatekeeper_configure(allowed_functions := [{'catalog':'system','schema_path':['main'],'name':'read_parquet'}])")
        result = validate(db, f"SELECT * FROM '{path}'")
        expect(result["allowed"] and result["objects"][0]["type"] == "replacement",
               f"granted replacement scan not recorded: {result}")
        db.execute("RESET gatekeeper_policy")

    # The policy setting round-trips through the host's DBConfig and prepared executions re-read it.
    db.execute("PREPARE p AS SELECT allowed FROM gatekeeper_validate('SELECT md5(s) FROM t')")
    expect(db.execute("EXECUTE p").fetchone() == (True,), "prepared validation did not allow md5")
    db.execute("CALL gatekeeper_configure(blocked_functions := [{catalog:'system',schema_path:['main'],name:'md5',type:'scalar'}])")
    expect(db.execute("EXECUTE p").fetchone() == (False,), "prepared validation did not re-read the policy")
    expect(db.execute("SELECT current_setting('gatekeeper_policy').blocked_functions").fetchone() == ([{"catalog":"system","schema_path":["main"],"name":"md5","type":"scalar"}],),
           "policy readback disagrees with the configured value")
    db.execute("SET lock_configuration = true")
    try:
        db.execute("CALL gatekeeper_configure()")
    except duckdb.Error as error:
        expect("locked" in str(error).lower(), f"unexpected lock error: {error}")
    else:
        raise SystemExit("::error::gatekeeper_configure ignored lock_configuration")

    enforcement(artifact)
    run_sql_smoke(artifact)
    print(artifact.name + ": loadable smoke checks passed")


def enforcement(artifact):
    """Enforced connections, log-only mode, and the audit log through the host's query hooks and log manager."""
    db = connect(artifact, autoload_known_extensions=False, autoinstall_known_extensions=False)
    db.execute("CREATE SCHEMA reporting; CREATE TABLE reporting.orders AS SELECT 20.0 AS amount")
    db.execute("CREATE TABLE secret AS SELECT 'x' AS token")
    db.execute("CALL gatekeeper_configure(allowed_tables := [{'schema_path': ['reporting'], 'table': '*'}])")
    db.execute("CALL enable_logging('Gatekeeper')")
    db.execute("SET logging_level = 'debug'")
    agent = db.cursor()
    enforced, warnings = agent.execute("SELECT enforced, warnings FROM gatekeeper_enforce()").fetchone()
    expect(enforced is True and isinstance(warnings, list), f"gatekeeper_enforce row: {(enforced, warnings)}")

    # The engine executes what the policy allows and refuses the rest before it runs, through the host's hooks.
    expect(agent.execute("SELECT sum(amount) FROM reporting.orders").fetchone() == (20.0,), "allowed read failed")
    for sql in ["SELECT * FROM secret", "CREATE TABLE u(x INTEGER)", "SET threads = 1", "CALL disable_logging()"]:
        try:
            agent.execute(sql).fetchall()
        except duckdb.PermissionException as error:
            expect("Gatekeeper denied" in str(error), f"{sql}: refused with the wrong error: {error}")
        else:
            raise SystemExit(f"::error::enforced connection executed: {sql}")
    expect(agent.execute("SELECT amount FROM reporting.orders WHERE amount > ?", [10]).fetchall() == [(20.0,)],
           "parameterized allowed read failed on the enforced connection")
    try:
        agent.execute("SELECT * FROM secret WHERE token = ?", ["x"]).fetchall()
    except duckdb.PermissionException:
        pass
    else:
        raise SystemExit("::error::parameterized denied read executed on the enforced connection")
    expect(db.execute("SELECT count(*) FROM secret").fetchone() == (1,), "host connection was enforced too")

    # Every decision is a record the host reads back; the allowed ones are DEBUG, so the level above is needed.
    rows = db.execute("""SELECT mode, allowed, code FROM duckdb_logs_parsed('Gatekeeper')
                         WHERE event = 'decision' ORDER BY allowed, code""").fetchall()
    expect(any(r == ("enforce", True, "ok") for r in rows) and any(r == ("enforce", False, "forbidden") for r in rows)
           and any(r == ("enforce", False, "unsupported") for r in rows), f"audit records: {rows}")
    denied = db.execute("""SELECT statement, violations[1].rule FROM duckdb_logs_parsed('Gatekeeper')
                           WHERE NOT allowed AND statement = 'SELECT * FROM secret'""").fetchone()
    expect(denied == ("SELECT * FROM secret", "table"), f"denied record: {denied}")

    # Log-only: the same decisions are recorded and nothing is refused; back to enforcing at the next statement.
    db.execute("CALL truncate_duckdb_logs()")
    db.execute("SET gatekeeper_log_only = true")
    expect(agent.execute("SELECT count(*) FROM secret").fetchone() == (1,), "log-only connection refused a read")
    record = db.execute("""SELECT mode, allowed, code FROM duckdb_logs_parsed('Gatekeeper')
                           WHERE statement = 'SELECT count(*) FROM secret'""").fetchone()
    expect(record == ("log_only", False, "forbidden"), f"log-only record: {record}")
    db.execute("SET gatekeeper_log_only = false")
    try:
        agent.execute("SELECT count(*) FROM secret").fetchall()
    except duckdb.PermissionException:
        pass
    else:
        raise SystemExit("::error::refusals did not resume after log-only was turned off")
    # Written order: two records can share a wall-clock timestamp, and context ids are allocated in sequence
    # (the convention of test/support/audit.py's records()).
    changes = db.execute("""SELECT event, new_value FROM duckdb_logs_parsed('Gatekeeper')
                            WHERE event = 'log_only_changed' ORDER BY timestamp, context_id""").fetchall()
    expect(changes == [("log_only_changed", "true"), ("log_only_changed", "false")], f"setting records: {changes}")
    db.close()


if __name__ == "__main__":
    main(sys.argv)
