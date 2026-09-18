"""Audit log: every decision Gatekeeper makes is a structured record of log type 'Gatekeeper'."""
import duckdb
import pytest

from test_enforcement import DENIED, PARITY_CORPUS, agent, catalog, enforce  # noqa: F401 (fixtures)
from test_gatekeeper import connect, db  # noqa: F401 (fixture)
from typed_helpers import configure, validate

RECORD_COLUMNS = ["event", "mode", "boundary", "allowed", "code", "violations", "error_type", "error_message",
                  "position", "objects", "functions", "statement", "statement_length", "policy_hash", "new_value"]


def records(host, where="true"):
    columns = ["connection_id", "query_id", "log_level"] + RECORD_COLUMNS
    result = host.execute(f"SELECT {', '.join(columns)} FROM duckdb_logs_parsed('Gatekeeper') "
                          f"WHERE {where} ORDER BY timestamp, context_id")
    return [dict(zip(columns, row)) for row in result.fetchall()]


def decisions(host, where="true"):
    return records(host, f"event = 'decision' AND ({where})")


def enable(host, level=None):
    host.execute("CALL enable_logging('Gatekeeper')")
    if level:
        # enable_logging(type, level := ...) resets the level to the type's declared level (INFO) after applying
        # the argument, so the level is lowered separately.
        host.execute(f"SET logging_level = '{level}'")


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
    # Third leg of the parity oracle: the record says what gatekeeper_validate says and what the agent saw.
    enable(catalog, "debug")
    expected = validate(catalog, sql)
    try:
        agent.execute(sql).fetchall()
        outcome = "allowed"
    except duckdb.Error as error:
        outcome = "denied" if DENIED.search(str(error)) else "engine"
    found = decisions(catalog, "mode = 'enforce'")
    if outcome == "engine":
        # Engine errors are DuckDB's, not decisions: nothing is recorded for them on the enforced path.
        assert found == [] or all(r["allowed"] for r in found), (sql, found)
        return
    assert len(found) == 1, (sql, found)
    record = found[0]
    assert record["allowed"] == expected["allowed"] == (outcome == "allowed"), (sql, record)
    assert record["code"] == expected["code"], (sql, record)
    assert record["violations"] == expected["violations"], (sql, record)
    assert record["log_level"] == ("DEBUG" if record["allowed"] else "INFO")
    # The record holds the statement the engine ran. DuckDB's preprocessor rewrites dynamic PIVOT (and query
    # pragmas) before any hook, so for those the text differs from what the caller wrote; see security.md.
    assert record["statement_length"] == len(record["statement"].encode())
    assert record["statement"] == sql or sql.startswith("PIVOT") or sql.startswith("PRAGMA"), (sql, record)
    if record["allowed"]:
        assert record["boundary"] == "execution"
        assert record["objects"] == expected["objects"] and record["functions"] == expected["functions"], (sql, record)
    else:
        assert record["boundary"] in {"binding", "authorize", "execution", "replacement_scan"}
        assert record["objects"] == [] and record["functions"] == []


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
    db.execute("SET gatekeeper_enforcement = 'off'")
    db.execute("SET gatekeeper_policy = {use_default_functions: true, allowed_functions: [], blocked_functions: ['md5'],"
               " allowed_tables: [], blocked_tables: [], restrict_tables: false}")
    found = records(db, "event LIKE '%_changed'")
    assert [(r["event"], r["log_level"]) for r in found] == [("enforcement_changed", "INFO"), ("policy_changed", "INFO")]
    assert found[0]["new_value"] == "off"
    assert "md5" in found[1]["new_value"]


def test_statement_text_is_capped_and_kept_parseable(db):
    enable(db)
    long_sql = "SELECT '" + "x" * 100000 + "'"
    assert validate(db, long_sql)["allowed"]
    db.execute("SET logging_level = 'debug'")
    validate(db, long_sql)
    # A NUL byte would truncate the record on the way into storage; it is replaced so the record still parses.
    db.execute("SELECT * FROM gatekeeper_validate('SELECT 1' || chr(0) || '2')").fetchall()
    capped, nul = decisions(db)
    assert capped["statement_length"] == len(long_sql) and len(capped["statement"]) == 65536
    assert long_sql.startswith(capped["statement"])
    assert nul["code"] == "invalid_input" and nul["statement"] == "SELECT 1\ufffd2" and nul["statement_length"] == 10


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
                "SET enable_logging = false", "SET logging_level = 'fatal'", "SET logging_storage = 'stdout'"]:
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql)
    # Never-bind: the host cannot allowlist them either.
    for name in ["enable_logging", "disable_logging", "truncate_duckdb_logs"]:
        result = validate(catalog, f"SELECT * FROM {name}()", {"allowed_functions": [name]})
        assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == name
    assert catalog.execute("SELECT current_setting('enable_logging')").fetchone() == (True,)


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
