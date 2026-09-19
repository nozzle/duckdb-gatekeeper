"""What Gatekeeper adds to a statement, measured against the same statement on a plain connection.

Every cell is the median wall-clock time of ``execute(...).fetchall()`` through the Python client, so the
plain-connection row carries the client round trip and the engine's own work and the other rows add
Gatekeeper's cost on top of the same thing. Three statement shapes separate what that cost scales with (the
statement: a second parse and bind, the AST walk) from what it does not (the data). ``--markdown`` prints the
table the README and the community descriptor carry; regenerate it whenever the engine pin moves.
"""
import argparse
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

import duckdb

from artifact import DEFAULT_EXTENSION, connect
from versions import EXTENSION_VERSION

WARMUP = 20
SMALL_ROWS = 1_000
BIG_ROWS = 10_000_000
NESTING = 20
IN_LIST = 2_000

SETUP = f"""
CREATE TABLE small AS SELECT range AS id, range % 97 AS k, random() AS v FROM range({SMALL_ROWS});
CREATE TABLE big AS SELECT range AS id, range % 97 AS k, random() AS v FROM range({BIG_ROWS});
CREATE SCHEMA secret;
CREATE TABLE secret.small AS SELECT * FROM small LIMIT 0;
CREATE TABLE secret.big AS SELECT * FROM big LIMIT 0;
CALL gatekeeper_configure(allowed_tables := [{{'catalog': '*', 'schema': 'main', 'table': '*'}}]);
"""


def large_statement(schema):
    """A NESTING-deep nested subquery over an IN_LIST-literal IN list: an agent-sized statement."""
    literals = ", ".join(str(value) for value in range(IN_LIST))
    return ("SELECT * FROM " + "(SELECT * FROM " * NESTING + f"{schema}small WHERE id IN ({literals})"
            + ") t" * NESTING)


# label -> statement template; ``schema`` is "" for the allowed tables in main and "secret." for the denied copies.
WORKLOADS = {
    f"point lookup ({SMALL_ROWS // 1_000} K rows)": lambda schema: f"SELECT v FROM {schema}small WHERE id = 500",
    f"aggregate ({BIG_ROWS // 1_000_000} M rows)":
        lambda schema: f"SELECT k, count(*), avg(v) FROM {schema}big GROUP BY k ORDER BY k",
    f"large statement ({len(large_statement('')) // 1024} KB)": large_statement,
}


def plain(db):
    cursor = db.cursor()
    return lambda sql: cursor.execute(sql).fetchall()


def enforced(db):
    cursor = db.cursor()
    cursor.execute("CALL gatekeeper_enforce()")
    return lambda sql: cursor.execute(sql).fetchall()


def enforced_with_audit_log(db):
    # Allowed decisions are DEBUG records; the default INFO level writes nothing on allowed traffic.
    db.execute("CALL enable_logging('Gatekeeper', level := 'debug')")
    return enforced(db)


def validate_then_execute(db):
    cursor = db.cursor()

    def run(sql):
        allowed, code = cursor.execute("SELECT allowed, code FROM gatekeeper_validate(?)", [sql]).fetchone()
        assert allowed and code == "ok", (allowed, code)
        return cursor.execute(sql).fetchall()
    return run


def denied(db):
    run_enforced = enforced(db)

    def run(sql):
        try:
            run_enforced(sql)
        except duckdb.PermissionException:
            return
        raise AssertionError("the statement was not refused: " + sql[:80])
    return run


BASELINE = "plain connection"
AUDIT_LOG = "enforced, audit log at debug"
DENIED = "denied on an enforced connection"
# label -> (prepare(db) -> run(sql), schema prefix of the tables the statements name)
MODES = {
    BASELINE: (plain, ""),
    "enforced connection": (enforced, ""),
    AUDIT_LOG: (enforced_with_audit_log, ""),
    "validate, then execute": (validate_then_execute, ""),
    DENIED: (denied, "secret."),
}


def measure(extension, iterations):
    """{mode label: {workload label: median microseconds}}.

    The modes take turns within every iteration, so drift over the run (thermal, other processes) lands on
    all of them alike and cancels in the differences. Enabling the log is instance-wide, so that mode gets a
    database of its own; the others share one, enforcement being per connection."""
    with connect(extension) as shared, connect(extension) as logged:
        shared.execute(SETUP)
        logged.execute(SETUP)
        for statement in WORKLOADS.values():
            # The denied copies exist, so a refusal is the policy's, not a missing table's.
            code = shared.execute("SELECT code FROM gatekeeper_validate(?)", [statement("secret.")]).fetchone()[0]
            assert code == "forbidden", code
        runners = {mode: prepare(logged if mode == AUDIT_LOG else shared) for mode, (prepare, _) in MODES.items()}
        results = {mode: {} for mode in MODES}
        for workload, statement in WORKLOADS.items():
            statements = {mode: statement(schema) for mode, (_, schema) in MODES.items()}
            samples = {mode: [] for mode in MODES}
            for iteration in range(WARMUP + iterations):
                for mode in MODES:
                    start = time.perf_counter_ns()
                    runners[mode](statements[mode])
                    if iteration >= WARMUP:
                        samples[mode].append((time.perf_counter_ns() - start) / 1_000)
            for mode in MODES:
                results[mode][workload] = statistics.median(samples[mode])
            logged.execute("CALL truncate_duckdb_logs()")
    return results


def duration(microseconds):
    return f"{microseconds / 1_000:.1f} ms" if microseconds >= 1_000 else f"{microseconds:.0f} µs"


def cell(mode, results, workload):
    value = results[mode][workload]
    if mode in (BASELINE, DENIED):
        return duration(value)
    delta = value - results[BASELINE][workload]
    return f"{duration(value)} ({'+' if delta >= 0 else '−'}{duration(abs(delta))})"


def machine():
    try:
        if sys.platform == "darwin":
            return subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
        if sys.platform.startswith("linux"):
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except (OSError, subprocess.CalledProcessError):
        pass
    return platform.processor() or platform.machine()


def footnote(iterations):
    return (f"Median of {iterations} runs per cell after {WARMUP} warm-ups, `execute().fetchall()` through the "
            f"Python client on one connection of an in-memory database; {machine()}, DuckDB "
            f"{duckdb.__version__}, Gatekeeper {EXTENSION_VERSION}. The plain row is the client round trip "
            "plus the engine's own work; in parentheses, what each mode adds to it.")


def markdown(results, iterations):
    lines = ["| | " + " | ".join(WORKLOADS) + " |", "| --- |" + " ---: |" * len(WORKLOADS)]
    for mode in MODES:
        lines.append(f"| {mode} | " + " | ".join(cell(mode, results, workload) for workload in WORKLOADS) + " |")
    return "\n".join(lines) + "\n\n" + footnote(iterations) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--extension", type=Path, default=DEFAULT_EXTENSION)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--markdown", action="store_true", help="print the table the README and descriptor carry")
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be positive")
    results = measure(args.extension, args.iterations)
    if args.markdown:
        print(markdown(results, args.iterations), end="")
        return
    print("DuckDB", duckdb.__version__, "Gatekeeper", EXTENSION_VERSION, "on", machine())
    for mode in MODES:
        print(mode + ": " + "; ".join(f"{workload} {cell(mode, results, workload)}" for workload in WORKLOADS))


if __name__ == "__main__":
    main()
