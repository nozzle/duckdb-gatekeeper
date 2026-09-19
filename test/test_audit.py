"""Audit log: every decision Gatekeeper makes is a structured record of log type 'Gatekeeper'."""
import concurrent.futures
import json
import threading

import duckdb
import pytest

from support.audit import RECORD_COLUMNS, decisions, enable, records
from support.corpus import PARITY_CORPUS
from support.enforcement import DENIED, attempt, enforce
from support.typed_helpers import configure, validate


def test_record_shape(db):
    enable(db)
    validate(db, "SELECT 1")
    columns = [c[0] for c in db.execute("SELECT * FROM duckdb_logs_parsed('Gatekeeper') LIMIT 0").description]
    # DuckDB's own context columns first, then the Gatekeeper record, with no duplicated names.
    assert columns[:9] == ["context_id", "scope", "connection_id", "transaction_id", "query_id", "thread_id",
                           "timestamp", "type", "log_level"]
    assert columns[9:] == RECORD_COLUMNS
    # Registration is what makes enable_logging('Gatekeeper') accept the name; an unknown type is refused.
    with pytest.raises(duckdb.InvalidInputException, match="Unknown log type"):
        db.execute("CALL enable_logging('Gatekeeper_missing')")


@pytest.mark.parametrize("sql", PARITY_CORPUS)
def test_records_agree_with_validate_and_the_error(catalog, agent, sql):
    # Second leg of the parity oracle: the record says what gatekeeper_validate says and what the agent saw.
    enable(catalog, "debug")
    expected = validate(catalog, sql)
    seen = attempt(agent, sql)
    found = decisions(catalog, "mode = 'enforce'")
    if seen.kind == "engine":
        # Engine errors are DuckDB's, not decisions: nothing is recorded for them on the enforced path.
        assert found == [] or all(r["allowed"] for r in found), (sql, found)
        return
    # A dynamic PIVOT runs as the statements DuckDB rewrites it into, each leaving its own record on its own
    # text, and enforcement stops at the first denied one; gatekeeper_validate decides the same statements in
    # the same order, so its row is that record, or describes the whole allowed set. Every other statement
    # leaves exactly one record, on the text as written.
    rewritten = [r for r in found if r["statement"] != sql]
    assert found and (len(found) == 1 or rewritten), (sql, found)
    assert not rewritten or "PIVOT" in sql or sql.startswith("PRAGMA"), (sql, found)
    denied = [r for r in found if not r["allowed"]]
    assert denied in ([], found[-1:]), (sql, found)
    record = denied[0] if denied else found[0]
    assert record["allowed"] == expected["allowed"] == (seen.kind == "rows"), (sql, record)
    assert record["code"] == expected["code"], (sql, record)
    assert record["violations"] == expected["violations"], (sql, record)
    for entry in found:
        assert entry["log_level"] == ("DEBUG" if entry["allowed"] else "INFO")
        assert entry["statement_length"] == len(entry["statement"].encode())
    if record["allowed"]:
        assert all(entry["boundary"] == "execution" for entry in found)
        assert union(found, "objects") == union([expected], "objects"), (sql, found)
        # The pivoting SELECT of a dynamic PIVOT is validated in both plan shapes DuckDB can choose, so the
        # functions gatekeeper_validate reports cover those the shape the data selected bound.
        if rewritten:
            assert set(union(found, "functions")) <= set(union([expected], "functions")), (sql, found)
        else:
            assert record["functions"] == expected["functions"], (sql, record)
    else:
        assert record["boundary"] in {"binding", "authorize", "execution", "replacement_scan"}
        assert record["objects"] == [] and record["functions"] == []


def union(records, column):
    return sorted({json.dumps(entry, sort_keys=True) for record in records for entry in record[column]})


def test_binding_denial_carries_the_text_and_the_connection_recovers(catalog, agent):
    enable(catalog)
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("INSERT INTO reporting.orders VALUES (9, 1.0, 'z')")
    [record] = decisions(catalog)
    assert record["boundary"] == "binding" and record["code"] == "unsupported"
    assert record["statement"] == "INSERT INTO reporting.orders VALUES (9, 1.0, 'z')"
    # DuckDB's own QueryLog entry is written after QueryBegin, so the denied text exists only in this record.
    assert catalog.execute("SELECT count(*) FROM duckdb_logs WHERE type = 'QueryLog' AND message LIKE 'INSERT%'"
                           ).fetchone()[0] == 0
    # A QueryBegin throw leaves the engine's query open until the next entry point (duckdb/duckdb#25876); the
    # connection's next statement must still run and be recorded normally.
    assert agent.execute("SELECT count(*) FROM reporting.orders").fetchone() == (3,)
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM secret.salaries")
    assert [r["boundary"] for r in decisions(catalog)] == ["binding", "authorize"]


def test_records_carry_the_connection_and_query_of_the_statement(catalog, agent):
    enable(catalog)
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM secret.salaries")
    validate(catalog, "SELECT * FROM secret.salaries")
    agent_id = agent.execute("SELECT 1").fetchone()  # noqa: F841 keeps the cursor alive
    enforced, validated = decisions(catalog)
    # DuckDB's context columns describe the connection that ran the statement, not the one reading the log.
    assert enforced["connection_id"] != validated["connection_id"]
    assert enforced["query_id"] is not None and validated["query_id"] is not None
    assert enforced["query_id"] != validated["query_id"]


def test_records_survive_enable_logging_on_a_connection_opened_earlier(catalog):
    # A connection's own logger is a snapshot refreshed only after the QueryBegin hooks run, so it is a
    # NopLogger for the first statement after enable_logging. The record is written through the database.
    with catalog.cursor() as agent:
        enforce(agent)
        enable(catalog)
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute("SELECT * FROM secret.salaries")
        assert [r["code"] for r in decisions(catalog)] == ["forbidden"]


def test_nothing_is_recorded_while_logging_is_off(catalog, agent):
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM secret.salaries")
    agent.execute("SELECT count(*) FROM reporting.orders").fetchall()
    enable(catalog, "debug")
    assert decisions(catalog) == []


def test_allowed_statements_are_debug_records_with_resolved_objects(catalog, agent):
    enable(catalog)
    agent.execute("SELECT * FROM reporting.totals").fetchall()
    assert decisions(catalog) == []
    catalog.execute("SET logging_level = 'debug'")
    agent.execute("SELECT reporting.twice(total) FROM reporting.totals").fetchall()
    [record] = decisions(catalog)
    assert record["log_level"] == "DEBUG" and record["boundary"] == "execution" and record["code"] == "ok"
    # The view and the base table it expands to, by resolved identity, and every resolved function.
    assert {(o["schema"], o["table"], o["type"]) for o in record["objects"]} == {
        ("reporting", "orders", "table"), ("reporting", "totals", "view")}
    assert {(f["name"], f["type"]) for f in record["functions"]} >= {("twice", "macro"), ("sum", "aggregate")}


def test_parameterized_statements_are_recorded_with_the_bound_decision(catalog, agent):
    enable(catalog, "debug")
    agent.execute("SELECT * FROM reporting.orders WHERE id = ?", [1]).fetchall()
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM secret.salaries WHERE who = ?", ["x"])
    allowed, denied = decisions(catalog)
    assert allowed["allowed"] and allowed["statement"] == "SELECT * FROM reporting.orders WHERE id = ?"
    assert denied["boundary"] == "authorize" and denied["violations"][0]["table"] == "salaries"
    assert denied["statement"] == "SELECT * FROM secret.salaries WHERE who = ?"


def test_replacement_scan_outside_the_private_bind_is_recorded_with_the_text(catalog, agent):
    # A parameterized statement is authorized after the engine binds, so the engine's own bind reaches the
    # replacement-scan gate first, outside Authorize: the gate decides and records on its own.
    enable(catalog)
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM '/nonexistent/gatekeeper.parquet' WHERE x = ?", [1])
    [record] = decisions(catalog)
    assert record["boundary"] == "replacement_scan" and record["code"] == "forbidden"
    assert record["violations"][0]["rule"] == "function" and record["violations"][0]["function_name"] == "read_parquet"
    assert record["statement"] == "SELECT * FROM '/nonexistent/gatekeeper.parquet' WHERE x = ?"


def test_validate_calls_are_recorded_without_a_boundary(db):
    enable(db, "debug")
    validate(db, "SELECT 1")
    validate(db, "DROP TABLE t")
    db.execute("SELECT * FROM gatekeeper_validate(NULL)").fetchall()
    allowed, denied, null = decisions(db)
    assert [r["mode"] for r in (allowed, denied, null)] == ["validate"] * 3
    assert all(r["boundary"] is None for r in (allowed, denied, null))
    assert allowed["log_level"] == "DEBUG" and allowed["statement"] == "SELECT 1"
    assert denied["log_level"] == "INFO" and denied["code"] == "unsupported" and denied["statement"] == "DROP TABLE t"
    assert null["code"] == "invalid_input" and null["statement"] is None and null["statement_length"] is None


def test_policy_hash_correlates_decisions_with_the_policy_in_force(catalog, agent):
    enable(catalog)
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM secret.salaries")
    configure(catalog, {"allowed_tables": [{"schema": "reporting", "table": "*"}, {"schema": "secret", "table": "*"}],
                        "blocked_functions": ["md5"]})
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT md5(who) FROM secret.salaries")
    [first, second] = decisions(catalog)
    [changed] = records(catalog, "event = 'policy_changed'")
    assert first["policy_hash"] != second["policy_hash"]
    assert second["policy_hash"] == changed["policy_hash"] and len(changed["policy_hash"]) == 16
    assert "'secret'" in changed["new_value"] or "secret" in changed["new_value"]
    assert changed["mode"] is None and changed["statement"] is None and changed["allowed"] is None


def test_setting_changes_are_recorded(db):
    enable(db)
    db.execute("SET gatekeeper_policy = {use_default_functions: true, allowed_functions: [], blocked_functions: ['md5'],"
               " allowed_tables: [], blocked_tables: [], restrict_tables: false}")
    db.execute("RESET gatekeeper_policy")
    found = records(db, "event LIKE '%_changed'")
    assert [(r["event"], r["log_level"]) for r in found] == [("policy_changed", "INFO"), ("policy_changed", "INFO")]
    assert "md5" in found[0]["new_value"]
    assert "md5" not in found[1]["new_value"]


def test_statement_text_is_capped_and_kept_parseable(db):
    enable(db)
    long_sql = "SELECT '" + "x" * 100000 + "'"
    assert validate(db, long_sql)["allowed"]
    db.execute("SET logging_level = 'debug'")
    validate(db, long_sql)
    # A NUL byte would truncate the record on the way into storage; it is replaced so the record still parses.
    db.execute("SELECT * FROM gatekeeper_validate('SELECT 1' || chr(0) || '2')").fetchall()
    # The cap bounds the stored bytes after NUL replacement: 70,000 NULs would otherwise store 210,000 bytes.
    db.execute("SELECT * FROM gatekeeper_validate('SELECT ' || chr(39) || repeat(chr(0), 70000) || chr(39))").fetchall()
    capped, nul, nuls = decisions(db)
    assert capped["statement_length"] == len(long_sql) and len(capped["statement"]) == 65536
    assert long_sql.startswith(capped["statement"])
    assert nul["code"] == "invalid_input" and nul["statement"] == "SELECT 1\ufffd2" and nul["statement_length"] == 10
    assert nuls["statement_length"] == 70009 and len(nuls["statement"].encode()) <= 65536
    assert nuls["statement"].startswith("SELECT '\ufffd") and set(nuls["statement"][8:]) == {"\ufffd"}


def test_multibyte_text_is_cut_on_a_character_boundary(db):
    enable(db, "debug")
    sql = "SELECT 'x" + "\u00e9" * 40000 + "'"  # 9 bytes then two per character: 65536 lands mid-character
    validate(db, sql)
    [record] = decisions(db)
    assert record["statement_length"] == len(sql.encode())
    assert record["statement"].encode() == sql.encode()[:65535]  # backed off one byte to the character boundary


def test_sandboxed_connection_cannot_reach_the_log(catalog, agent):
    enable(catalog)
    for sql in ["SELECT * FROM duckdb_logs", "SELECT * FROM duckdb_logs_parsed('Gatekeeper')",
                "SELECT * FROM duckdb_log_contexts()", "CALL disable_logging()", "SELECT * FROM disable_logging()",
                "SELECT * FROM truncate_duckdb_logs()", "CALL truncate_duckdb_logs()",
                "SELECT * FROM enable_logging(storage := 'file', storage_path := '/tmp/gatekeeper_agent.csv')",
                "SELECT write_log('forged', log_type := 'Gatekeeper', level := 'info')",
                "SET enable_logging = false", "SET logging_level = 'fatal'", "SET logging_storage = 'stdout'"]:
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql)
    # Never-bind: the host cannot allowlist them either.
    for name, call in [("enable_logging", "SELECT * FROM enable_logging()"),
                       ("disable_logging", "SELECT * FROM disable_logging()"),
                       ("truncate_duckdb_logs", "SELECT * FROM truncate_duckdb_logs()"),
                       ("write_log", "SELECT write_log('x', log_type := 'Gatekeeper')")]:
        result = validate(catalog, call, {"allowed_functions": [name]})
        assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == name, (name, result)
    assert catalog.execute("SELECT current_setting('enable_logging')").fetchone() == (True,)
    # Nothing above reached the log: every Gatekeeper-typed entry is one of Gatekeeper's own records.
    for record in records(catalog):
        assert record["event"] == "decision" and not record["allowed"]


def test_write_log_forgery_is_refused_even_when_allowlisted(catalog, agent):
    # write_log writes any message under any log type. With it allowlisted, an agent could plant a
    # Gatekeeper-typed entry that forges a decision or that duckdb_logs_parsed cannot cast, which would
    # break the reader for the host. Never-bind keeps it unreachable whatever the policy says.
    enable(catalog)
    configure(catalog, {"allowed_tables": [{"schema": "reporting", "table": "*"}], "allowed_functions": ["write_log"]})
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT write_log('not-a-struct', log_type := 'Gatekeeper', level := 'info')").fetchall()
    assert all(r["event"] in {"decision", "policy_changed"} for r in records(catalog))
    assert catalog.execute("SELECT count(*) FROM duckdb_logs WHERE type = 'Gatekeeper' AND message = 'not-a-struct'"
                           ).fetchone()[0] == 0


@pytest.mark.xfail(strict=True, reason="the engine evaluates PRAGMA argument expressions in the statement "
                                       "preprocessor before any extension hook runs (nozzle/duckdb-gatekeeper#46)")
def test_pragma_preprocessing_cannot_forge_a_record(catalog, agent):
    # Pins the audit-integrity residual: the never-bind list cannot reach the preprocessor. Strict, so an engine
    # repin that closes the gap fails here; then remove the xfail and the residual wording in
    # docs/security.md#audit-log.
    enable(catalog)
    # write_log goes through the connection's own logger, which is refreshed at query end; a fresh cursor
    # opened before enable_logging still holds a NopLogger, so run one statement first as a real agent would.
    agent.execute("SELECT count(*) FROM reporting.orders").fetchall()
    with pytest.raises(duckdb.Error):
        agent.execute("PRAGMA no_such_pragma(write_log('forged', log_type := 'Gatekeeper', level := 'info'))")
    assert catalog.execute("SELECT count(*) FROM duckdb_logs WHERE type = 'Gatekeeper' AND message = 'forged'"
                           ).fetchone()[0] == 0


def test_posture_warning_names_the_log(catalog):
    with catalog.cursor() as unlogged:
        assert any("enable_logging('Gatekeeper')" in w for w in enforce(unlogged))
    enable(catalog)
    with catalog.cursor() as logged:
        assert not any("enable_logging" in w for w in enforce(logged))
    catalog.execute("SET logging_level = 'error'")
    with catalog.cursor() as filtered:
        assert any("enable_logging('Gatekeeper')" in w for w in enforce(filtered))


def test_file_storage_receives_records(catalog, agent, tmp_path):
    path = tmp_path / "gatekeeper.csv"
    catalog.execute("CALL enable_logging('Gatekeeper', storage := 'file', storage_path := ?)", [str(path)])
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM secret.salaries")
    catalog.execute("CALL disable_logging()")  # flushes
    text = path.read_text()
    assert "Gatekeeper" in text and "SELECT * FROM secret.salaries" in text and "object is not allowed" in text


def test_replacement_gate_uses_the_statement_snapshot_under_policy_flips(catalog, tmp_path):
    # A parameterized statement is authorized after the engine binds, so the engine's own bind reaches the
    # replacement-scan gate first, outside the private bind, in the window after QueryBegin snapshotted the
    # policy. The gate must decide under that snapshot, not a fresh read of the setting: with a fresh read, a
    # flip landing in the window let the gate admit the reader under the new policy and the private bind then
    # deny it under the snapshot, an 'authorize' denial this statement can never otherwise produce. With the
    # snapshot, every denial is the gate's, and the hash on each record agrees with the decision.
    path = tmp_path / "flip.parquet"
    catalog.execute("COPY (SELECT range AS x FROM range(3)) TO ? (FORMAT parquet)", [str(path)])
    tables = [{"schema": "reporting", "table": "*"}]
    reader_allowed = {"allowed_tables": tables, "allowed_functions": ["read_parquet"]}
    reader_denied = {"allowed_tables": tables}
    enable(catalog, "debug")
    configure(catalog, reader_denied)  # both policies are installed after logging is on, so both hashes are recorded
    statement = f"SELECT * FROM '{path}' WHERE x = ?"
    stop = threading.Event()
    errors = []

    def worker():
        with catalog.cursor() as cursor:
            enforce(cursor)
            while not stop.is_set():
                try:
                    cursor.execute(statement, [1]).fetchall()
                except duckdb.PermissionException:
                    pass
                except duckdb.Error as error:
                    errors.append(str(error))

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(worker) for _ in range(4)]
        for i in range(60):
            configure(catalog, reader_allowed if i % 2 else reader_denied)
        stop.set()
        for future in futures:
            future.result()
    assert errors == []
    hashes = {r["policy_hash"]: "read_parquet" in r["new_value"] for r in records(catalog, "event = 'policy_changed'")}
    assert set(hashes.values()) == {True, False}
    found = [r for r in decisions(catalog, "mode = 'enforce'") if r["statement"] == statement]
    assert found and any(r["allowed"] for r in found) and any(not r["allowed"] for r in found)
    for record in found:
        assert record["policy_hash"] in hashes, record
        # The decision is the one the snapshot dictates, and the record names that snapshot.
        assert record["allowed"] == hashes[record["policy_hash"]], record
        assert record["boundary"] == ("execution" if record["allowed"] else "replacement_scan"), record


def test_reset_is_recorded_with_the_default_value(catalog, agent):
    # DuckDB's RESET invokes an extension option's set callback with the default value (physical_reset.cpp),
    # so it is recorded like SET. Only native DBConfig::SetOption writes bypass the callback; those stay
    # visible through the next decision's policy_hash, which is why every decision carries one.
    enable(catalog)
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM duckdb_settings()")  # never-bind: denied under any policy
    catalog.execute("RESET gatekeeper_policy")
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM duckdb_settings()")
    [changed] = records(catalog, "event = 'policy_changed'")
    assert "'restrict_tables': false" in changed["new_value"]
    before, after = decisions(catalog)
    assert before["policy_hash"] != after["policy_hash"] == changed["policy_hash"]
