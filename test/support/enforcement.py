"""Enforced connections: the latch, and how a statement's fate on one is observed."""
import re
from typing import NamedTuple, Optional

import duckdb

from support.artifact import ENGINE_MAJOR

# The message every Gatekeeper refusal carries; the engine's own errors never do.
DENIED = re.compile(r"Gatekeeper denied this statement")


def enforce(connection):
    """Latch ``connection`` into enforcement; returns the posture warnings."""
    row = connection.execute("CALL gatekeeper_enforce()").fetchone()
    assert row[0] is True
    return row[1]


def settle(connection):
    """End the query a refusal at the text boundary left open on ``connection`` (DuckDB 2.0 only).

    DuckDB begins the statement's auto-commit transaction before asking the registered states' QueryBegin, and
    when one of them throws (a Gatekeeper denial at the text boundary) it returns the error without ending the
    query (ClientContext::BeginQueryInternal's caller). The next plain statement's InitialCleanup ends it; but
    a statement the engine rewrites before that (a PRAGMA, a dynamic PIVOT, a relation) is preprocessed inside
    the transaction first and fails as "Current transaction is aborted". DuckDB 1.5 had the same sequence and
    no symptom, since a Permission Error did not invalidate the transaction there. Until the engine ends the
    query on that path, a test that follows a denial with such a statement runs one plain statement first."""
    if ENGINE_MAJOR >= 2:
        connection.execute("SELECT 1").fetchall()


class Outcome(NamedTuple):
    """What a connection did with a statement: ran it ("rows"), refused it as Gatekeeper ("denied"), or
    failed it in DuckDB's own words ("engine"). ``error`` is the exception for the latter two."""
    kind: str
    rows: Optional[list]
    error: Optional[duckdb.Error]


def attempt(connection, sql, parameters=None):
    try:
        rows = connection.execute(sql, parameters).fetchall()
    except duckdb.Error as error:
        return Outcome("denied" if DENIED.search(str(error)) else "engine", None, error)
    return Outcome("rows", rows, None)


def engine_code(error):
    """The ``code`` gatekeeper_validate reports for an engine error the text raised: ``parser`` when the parser
    refused it, ``binding`` once the text was admitted and the private bind failed (engine_errors.hpp)."""
    return "parser" if isinstance(error, duckdb.ParserException) else "binding"
