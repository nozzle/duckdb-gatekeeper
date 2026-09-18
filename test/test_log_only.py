"""Log-only mode: enforced connections make and record every decision, and refuse nothing."""
import re
import threading

import duckdb
import pytest

from test_audit import decisions, enable, records
from test_enforcement import CATALOG_POLICY, CATALOG_SQL, DENIED, PARITY_CORPUS, agent, catalog, enforce  # noqa: F401
from test_gatekeeper import connect, db  # noqa: F401 (fixture)
from typed_helpers import configure, validate


def fresh_catalog(log_only):
    connection = connect()
    connection.execute(CATALOG_SQL)
    configure(connection, CATALOG_POLICY)
    enable(connection, "debug")
    connection.execute(f"SET gatekeeper_log_only = {'true' if log_only else 'false'}")
    return connection


PIVOT_ENUM = re.compile(r"__pivot_enum_[0-9a-f-]+")
QUERY_LOCATION = re.compile(r"\n\nLINE \d+:.*", re.DOTALL)


def outcome(connection, sql):
    try:
        rows = connection.execute(sql).fetchall()
    except duckdb.Error as error:
        # DuckDB names a dynamic PIVOT's enum type after a fresh UUID; the engine's own error text carries it.
        # An enforced connection also binds a copy of the statement (its state can request a rebind), and
        # DuckDB's PivotRef::Copy drops the query location, so a binder error raised at a PIVOT loses its LINE
        # excerpt there (see docs/security.md, "Errors are informative"); compare the message without it.
        message = QUERY_LOCATION.sub("", PIVOT_ENUM.sub("__pivot_enum_", str(error)))
        return ("error", type(error).__name__, message)
    if sql.startswith("EXPLAIN ANALYZE"):
        return ("ok",)  # timings differ run to run
    if "USING SAMPLE" in sql:
        return ("ok", len(rows))
    return ("ok", sorted(rows, key=repr))  # unordered statements may return rows in any order


def quoted(sql):
    return "'" + sql.replace("'", "''") + "'"


@pytest.mark.parametrize("sql", PARITY_CORPUS)
def test_log_only_connection_behaves_like_an_unenforced_one_and_records_what_validate_says(sql):
    # Two-sided parity on identical fresh instances: the caller sees exactly what an unenforced connection
    # shows (rows, or DuckDB's own error, never a Gatekeeper denial), and the one record the statement leaves
    # is the gatekeeper_validate row for it.
    with fresh_catalog(True) as plain_host, fresh_catalog(True) as host:
        expected = validate(host, sql)
        with host.cursor() as observed:
            enforce(observed)
            seen = outcome(observed, sql)
        assert seen == outcome(plain_host.cursor(), sql), (sql, seen)
        assert seen[0] == "ok" or not DENIED.search(seen[2]), seen
        found = decisions(host, "mode = 'log_only'")
        if seen[0] == "error" and not found:
            # DuckDB's own parser rejected the text before any hook ran; there was never a statement to decide.
            assert expected["code"] == "parser", (sql, expected)
            return
        # A dynamic PIVOT is rewritten into a batch before any hook runs; each rewritten statement then runs
        # and leaves its own record. gatekeeper_validate decides the same statements in the same order, so its
        # row is the first denied record, or every record is allowed with it.
        rewritten = [r for r in found if r["statement"] != sql]
        assert len(found) == 1 or (rewritten and "PIVOT" in sql), (sql, found)
        assert not rewritten or "PIVOT" in sql or sql.startswith("PRAGMA"), (sql, found)
        denied = [r for r in found if not r["allowed"]]
        record = denied[0] if denied else found[0]
        assert record["allowed"] == expected["allowed"], (sql, record)
        assert record["code"] == expected["code"], (sql, record)
        assert record["violations"] == expected["violations"], (sql, record)
        for entry in found:
            assert entry["log_level"] == ("DEBUG" if entry["allowed"] else "INFO")
        assert decisions(host, "mode = 'enforce'") == []


def test_log_only_records_are_what_enforcement_would_have_refused(catalog, agent):
    # The same statement, decided both ways: identical records apart from the mode, and only one of them refused.
    enable(catalog, "debug")
    for sql in ["CREATE TABLE u(x INTEGER)", "SELECT * FROM secret.salaries", "SELECT md5('x')",
                "SELECT sum(amount) FROM reporting.orders", "SELECT * FROM reporting.orders WHERE id = ?"]:
        catalog.execute("SET gatekeeper_log_only = false")
        strict = outcome(agent, sql) if "?" not in sql else outcome_with(agent, sql, [1])
        catalog.execute("SET gatekeeper_log_only = true")
        relaxed = outcome(agent, sql) if "?" not in sql else outcome_with(agent, sql, [1])
        [enforced] = decisions(catalog, f"mode = 'enforce' AND statement = {quoted(sql)}")
        [logged] = decisions(catalog, f"mode = 'log_only' AND statement = {quoted(sql)}")
        for column in ["boundary", "allowed", "code", "violations", "objects", "functions", "policy_hash"]:
            assert enforced[column] == logged[column], (sql, column)
        if enforced["allowed"]:
            assert strict == relaxed and strict[0] == "ok"
        else:
            assert strict[0] == "error" and DENIED.search(strict[2]), (sql, strict)
            assert relaxed[0] == "ok", (sql, relaxed)
    assert catalog.execute("SELECT count(*) FROM duckdb_tables() WHERE table_name = 'u'").fetchone() == (1,)


def outcome_with(connection, sql, parameters):
    try:
        return ("ok", connection.execute(sql, parameters).fetchall())
    except duckdb.Error as error:
        return ("error", type(error).__name__, str(error))


def test_flip_applies_at_the_next_statement_in_both_directions(catalog, agent):
    enable(catalog)
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM secret.salaries")
    catalog.execute("SET gatekeeper_log_only = true")
    assert agent.execute("SELECT * FROM secret.salaries").fetchall() == [("x", 1.0)]
    catalog.execute("SET gatekeeper_log_only = false")
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM secret.salaries")
    catalog.execute("SET gatekeeper_log_only = true")
    assert agent.execute("SELECT * FROM secret.salaries").fetchall() == [("x", 1.0)]
    catalog.execute("RESET gatekeeper_log_only")
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM secret.salaries")
    assert [r["mode"] for r in decisions(catalog)] == ["enforce", "log_only", "enforce", "log_only", "enforce"]
    changes = records(catalog, "event = 'log_only_changed'")
    assert [(r["new_value"], r["log_level"]) for r in changes] == [("true", "INFO"), ("false", "INFO"),
                                                                    ("true", "INFO"), ("false", "INFO")]
    assert all(r["mode"] is None and r["statement"] is None and r["allowed"] is None for r in changes)


def test_exactly_one_record_per_statement_at_the_boundary_that_decided_it(catalog, agent, tmp_path):
    enable(catalog, "debug")
    catalog.execute("SET gatekeeper_log_only = true")
    path = tmp_path / "rows.csv"
    path.write_text("a,b\n1,2\n")
    cases = [
        ("CREATE TABLE u(x INTEGER)", "binding", "unsupported"),
        ("SELECT md5('x')", "binding", "forbidden"),
        ("SELECT * FROM secret.salaries", "authorize", "forbidden"),
        (f"SELECT * FROM '{path}'", "authorize", "forbidden"),
        ("SELECT sum(amount) FROM reporting.orders", "execution", "ok"),
    ]
    for sql, boundary, code in cases:
        agent.execute(sql).fetchall()
        found = decisions(catalog, f"statement = {quoted(sql)}")
        assert [(r["boundary"], r["code"]) for r in found] == [(boundary, code)], (sql, found)
    # A batch is one statement at a time, each with its own text and record, and none of them stops the batch.
    assert agent.execute("SELECT 1; CREATE TABLE v(x INTEGER); SELECT 2").fetchall() == [(2,)]
    found = decisions(catalog, "trim(statement) IN ('SELECT 1', 'CREATE TABLE v(x INTEGER)', 'SELECT 2')")
    assert [(r["statement"].strip(), r["boundary"], r["code"]) for r in found] == [
        ("SELECT 1", "execution", "ok"), ("CREATE TABLE v(x INTEGER)", "binding", "unsupported"),
        ("SELECT 2", "execution", "ok")]
    # Parameters defer authorization to the engine's bind: a reader is decided at the replacement gate the
    # engine's bind reaches first, everything else in PostBind with the bound values. Once either way.
    agent.execute(f"SELECT * FROM '{path}' WHERE a = ?", [1]).fetchall()
    agent.execute("SELECT * FROM secret.salaries WHERE amount > ?", [0]).fetchall()
    agent.execute("SELECT id FROM reporting.orders WHERE id = ?", [1]).fetchall()
    found = decisions(catalog, "statement LIKE '%?%'")
    assert [(r["boundary"], r["code"]) for r in found] == [("replacement_scan", "forbidden"),
                                                            ("authorize", "forbidden"), ("execution", "ok")]
    # The relation API goes through the same hooks with the relation's SQL rendering.
    assert agent.table("secret.salaries").fetchall() == [("x", 1.0)]
    assert [r["statement"] for r in decisions(catalog, "statement LIKE '%\"secret\"%'")] == ['SELECT * FROM "secret".salaries']
    # executemany prepares once outside any query, which is pre-screened at the prepare boundary (no text is
    # available there), then executes twice inside queries: one record per engine operation, none refused.
    agent.executemany("SELECT * FROM secret.salaries WHERE amount > ?", [[0], [0]])
    assert agent.fetchall() == [("x", 1.0)]
    found = decisions(catalog, "boundary = 'prepare' OR statement = 'SELECT * FROM secret.salaries WHERE amount > ?'")
    assert [(r["boundary"], r["code"], r["statement"] is None) for r in found] == [
        ("authorize", "forbidden", False),  # the execute() above
        ("prepare", "forbidden", True), ("authorize", "forbidden", False), ("authorize", "forbidden", False)]
    assert found[1]["violations"][0]["rule"] == "table"
    assert len(decisions(catalog, "mode = 'log_only' AND NOT allowed")) == 4 + 1 + 2 + 1 + 3
    # Both tables were created: log-only refused nothing.
    assert catalog.execute("SELECT count(*) FROM duckdb_tables() WHERE table_name IN ('u', 'v')").fetchone() == (2,)


def test_a_reader_that_fails_to_bind_is_still_recorded(catalog, agent):
    # A parameterized statement is authorized after the engine binds, so the engine's own bind reaches the
    # replacement gate first. With a file that does not exist the bind then fails before PostBind: the gate is
    # the only place the reader can be recorded, and it must be, in both modes, with the same record.
    enable(catalog)
    sql = "SELECT * FROM '/nonexistent/review52.parquet' WHERE x = ?"
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute(sql, [1])
    catalog.execute("SET gatekeeper_log_only = true")
    strict, relaxed = outcome_with(agent, sql, [1]), outcome_with(catalog.cursor(), sql, [1])
    assert strict == relaxed and strict[:2] == ("error", "IOException"), (strict, relaxed)
    [enforced, logged] = decisions(catalog)
    assert (enforced["mode"], logged["mode"]) == ("enforce", "log_only")
    for column in ["boundary", "code", "violations", "statement", "policy_hash"]:
        assert enforced[column] == logged[column], column
    assert logged["boundary"] == "replacement_scan" and logged["violations"][0]["function_name"] == "read_parquet"
    assert logged["statement"] == sql
    # The same through Prepare(): the gate decides the bind outside any statement (no text is available), the
    # failed bind runs no pre-screen, and the mark it left is cleared with that prepare attempt, so the next
    # Prepare() is decided on its own, whether or not a statement or transaction boundary came between.
    with pytest.raises(duckdb.IOException):
        agent.executemany(sql, [[1]])
    agent.executemany("SELECT * FROM secret.salaries WHERE amount > ?", [[0]])
    found = decisions(catalog, "mode = 'log_only'")[1:]
    assert [(r["boundary"], r["statement"]) for r in found] == [("replacement_scan", None), ("prepare", None),
                                                                 ("authorize", "SELECT * FROM secret.salaries WHERE amount > ?")]
    # Inside an explicit transaction no statement or transaction boundary separates two Prepare() calls (the
    # first failure aborts the transaction, and Prepare() still binds in an aborted one).
    agent.execute("BEGIN")
    for _ in range(2):
        with pytest.raises(duckdb.IOException):
            agent.executemany(sql, [[1]])
    agent.execute("ROLLBACK")
    agent.executemany("SELECT * FROM secret.salaries WHERE amount > ?", [[0]])
    found = decisions(catalog, "mode = 'log_only'")[4:]
    assert [(r["boundary"], r["statement"]) for r in found] == [
        ("binding", "BEGIN"), ("replacement_scan", None), ("replacement_scan", None), ("binding", "ROLLBACK"),
        ("prepare", None), ("authorize", "SELECT * FROM secret.salaries WHERE amount > ?")]


@pytest.mark.parametrize("sql, error", [
    ("SELECT * FROM reporting.missing WHERE id = ?", duckdb.CatalogException),
    ("SELECT no_such_column FROM reporting.orders WHERE id = ?", duckdb.BinderException),
    ("SELECT id FROM reporting.orders WHERE id = ? AND amount > DATE '2024-01-01'", duckdb.BinderException),
])
def test_a_parameterized_statement_the_engine_cannot_bind_is_still_recorded(catalog, agent, sql, error):
    # Parameters defer the private bind to PostBind, so when the engine's own bind fails nothing later runs.
    # Enforcing, that failure is DuckDB's error and no decision. Log-only, the statement must still appear in
    # the trail: it is recorded from the planning-error hook as gatekeeper_validate reports it, and the
    # engine's exception propagates exactly as on an unenforced connection.
    enable(catalog)
    expected = validate(catalog, sql)
    assert expected["code"] == "binding", expected
    with pytest.raises(error):
        agent.execute(sql, [1])
    assert decisions(catalog, "mode <> 'validate'") == []
    catalog.execute("SET gatekeeper_log_only = true")
    strict, relaxed = outcome_with(agent, sql, [1]), outcome_with(catalog.cursor(), sql, [1])
    assert strict == relaxed and strict[0] == "error" and strict[1] == error.__name__, (strict, relaxed)
    [record] = decisions(catalog, "mode <> 'validate'")
    assert (record["mode"], record["boundary"], record["allowed"], record["code"]) == ("log_only", "authorize", False, "binding")
    assert record["error_type"] == expected["error_type"] and record["statement"] == sql
    assert expected["error_message"].startswith(record["error_message"].split("\n")[0])


def test_a_statement_the_engine_rejects_before_planning_is_still_recorded(catalog, agent):
    # Parameters the caller did not supply fail the engine's own checks after QueryBegin admitted the text and
    # before any plan exists: no PostBind, no planning error. The query-end hook records it, without a query id
    # (the engine has closed the query by then), so the trail is complete in every path.
    enable(catalog)
    catalog.execute("SET gatekeeper_log_only = true")
    cases = [("SELECT $1", None), ("SELECT * FROM reporting.orders WHERE id = ?", [1, 2])]
    for sql, args in cases:
        relaxed = outcome_with(agent, sql, args) if args else outcome(agent, sql)
        plain = outcome_with(catalog.cursor(), sql, args) if args else outcome(catalog.cursor(), sql)
        assert relaxed == plain and relaxed[:2] == ("error", "InvalidInputException"), (relaxed, plain)
    found = decisions(catalog)
    assert [(r["boundary"], r["code"], r["error_type"], r["statement"], r["query_id"]) for r in found] == [
        ("authorize", "binding", "Invalid Input", "SELECT $1", None),
        ("authorize", "binding", "Invalid Input", "SELECT * FROM reporting.orders WHERE id = ?", None)]
    assert all(r["statement_length"] == len(r["statement"]) for r in found)


def test_prepared_statements_are_recorded_when_prepared_and_when_executed(catalog, agent):
    enable(catalog, "debug")
    catalog.execute("SET gatekeeper_log_only = true")
    # SQL-level PREPARE is an unsupported statement type; in log-only mode it is recorded and prepared.
    agent.execute("PREPARE leak AS SELECT * FROM secret.salaries WHERE amount > $1")
    assert agent.execute("EXECUTE leak(0)").fetchall() == [("x", 1.0)]
    found = decisions(catalog)
    assert [(r["boundary"], r["code"]) for r in found] == [("binding", "unsupported"), ("binding", "unsupported")]
    assert found[0]["statement"].startswith("PREPARE") and found[1]["statement"] == "EXECUTE leak(0)"
    catalog.execute("SET gatekeeper_log_only = false")
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("EXECUTE leak(0)")


def test_log_only_protects_nothing_including_gatekeeper_itself(catalog, agent):
    enable(catalog)
    catalog.execute("SET gatekeeper_log_only = true")
    # The enforced connection can now reach the policy and the switch; each attempt is on the record.
    agent.execute("SET gatekeeper_policy = {use_default_functions: true, allowed_functions: [], blocked_functions: [],"
                  " allowed_tables: [], blocked_tables: [], restrict_tables: false}")
    assert agent.execute("SELECT * FROM secret.salaries").fetchall() == [("x", 1.0)]
    assert [r["code"] for r in decisions(catalog, "statement LIKE 'SET gatekeeper_policy%'")] == ["unsupported"]
    assert len(records(catalog, "event = 'policy_changed'")) == 1
    # Turning refusals back on from the sandbox tightens it; the next statement is refused.
    agent.execute("SET gatekeeper_log_only = false")
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SET gatekeeper_log_only = true")
    # lock_configuration is the mitigation, as for the policy: the SET fails with the engine's error, is still
    # recorded as a would-be denial, and changes nothing.
    catalog.execute("SET gatekeeper_log_only = true; SET lock_configuration = true")
    with pytest.raises(duckdb.InvalidInputException, match="locked"):
        agent.execute("SET gatekeeper_log_only = false")
    with pytest.raises(duckdb.InvalidInputException, match="locked"):
        agent.execute("CALL gatekeeper_configure()")
    assert agent.execute("SELECT * FROM secret.salaries").fetchall() == [("x", 1.0)]
    assert len(decisions(catalog, "statement = 'SET gatekeeper_log_only = false' AND NOT allowed")) == 2


def test_setting_is_global_boolean_and_recorded(db):
    enable(db)
    assert db.execute("SELECT current_setting('gatekeeper_log_only')").fetchone() == (False,)
    assert db.execute("SELECT description FROM duckdb_settings() WHERE name = 'gatekeeper_log_only'").fetchone()[0]
    for statement in ["SET SESSION gatekeeper_log_only = true", "SET LOCAL gatekeeper_log_only = true",
                      "SET gatekeeper_log_only = NULL", "SET gatekeeper_log_only = 'sometimes'"]:
        with pytest.raises(duckdb.Error):
            db.execute(statement)
        assert db.execute("SELECT current_setting('gatekeeper_log_only')").fetchone() == (False,)
    db.execute("SET GLOBAL gatekeeper_log_only = true")
    db.execute("SET gatekeeper_log_only = 'false'")
    db.execute("SET gatekeeper_log_only = 1")
    db.execute("RESET gatekeeper_log_only")
    assert [r["new_value"] for r in records(db, "event = 'log_only_changed'")] == ["true", "false", "true", "false"]
    db.execute("SET lock_configuration = true")
    with pytest.raises(duckdb.InvalidInputException, match="locked"):
        db.execute("SET gatekeeper_log_only = true")


def test_posture_warning_names_the_switch(db):
    warnings = enforce(db.cursor())
    assert not any("gatekeeper_log_only is true" in w for w in warnings)
    assert any("lock_configuration" in w and "gatekeeper_log_only" in w for w in warnings)
    db.execute("SET gatekeeper_log_only = true")
    warnings = enforce(db.cursor())
    assert warnings[0] == "gatekeeper_log_only is true: this connection records decisions and refuses nothing"


def test_concurrent_flips_never_leave_a_statement_unrecorded_or_half_decided(catalog):
    # Workers hammer a statement the policy always denies while the host flips the switch. Every outcome must be
    # one of exactly two: a Gatekeeper denial recorded as mode 'enforce', or rows recorded as mode 'log_only',
    # with the counts matching the log to the statement.
    enable(catalog)
    stop = threading.Event()
    lock = threading.Lock()
    counts = {"denied": 0, "rows": 0, "other": []}

    def worker():
        with catalog.cursor() as cursor:
            enforce(cursor)
            while not stop.is_set():
                try:
                    rows = cursor.execute("SELECT * FROM secret.salaries").fetchall()
                    with lock:
                        counts["rows"] += 1 if rows == [("x", 1.0)] else 0
                        if rows != [("x", 1.0)]:
                            counts["other"].append(rows)
                except duckdb.PermissionException as error:
                    with lock:
                        counts["denied"] += 1 if DENIED.search(str(error)) else 0
                        if not DENIED.search(str(error)):
                            counts["other"].append(str(error))
                except duckdb.Error as error:
                    with lock:
                        counts["other"].append(str(error))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    try:
        for i in range(40):
            catalog.execute(f"SET gatekeeper_log_only = {'true' if i % 2 == 0 else 'false'}")
    finally:
        stop.set()
        for thread in threads:
            thread.join()
    assert counts["other"] == []
    assert counts["rows"] > 0 and counts["denied"] > 0
    enforced = decisions(catalog, "mode = 'enforce' AND NOT allowed")
    logged = decisions(catalog, "mode = 'log_only' AND NOT allowed")
    assert len(enforced) == counts["denied"] and len(logged) == counts["rows"]
    assert decisions(catalog, "allowed") == []
