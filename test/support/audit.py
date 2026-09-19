"""Reading Gatekeeper's records back out of DuckDB's log."""

# The Gatekeeper record, after DuckDB's own context columns.
RECORD_COLUMNS = ["event", "mode", "boundary", "allowed", "code", "violations", "error_type", "error_message",
                  "position", "objects", "functions", "statement", "statement_length", "policy_hash", "new_value"]


def records(host, where="true"):
    """Every Gatekeeper-typed record ``where`` selects, in the order it was written."""
    columns = ["connection_id", "query_id", "log_level"] + RECORD_COLUMNS
    result = host.execute(f"SELECT {', '.join(columns)} FROM duckdb_logs_parsed('Gatekeeper') "
                          f"WHERE {where} ORDER BY timestamp, context_id")
    return [dict(zip(columns, row)) for row in result.fetchall()]


def decisions(host, where="true"):
    return records(host, f"event = 'decision' AND ({where})")


def enable(host, level=None):
    """Turn the Gatekeeper log on; ``level`` lowers logging_level (for instance to "debug") afterwards."""
    host.execute("CALL enable_logging('Gatekeeper')")
    if level:
        # enable_logging(type, level := ...) resets the level to the type's declared level (INFO) after applying
        # the argument, so the level is lowered separately.
        host.execute(f"SET logging_level = '{level}'")
