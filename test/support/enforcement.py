"""Enforced connections: the latch, and how a statement's fate on one is observed."""
import re
from typing import NamedTuple, Optional

import duckdb

# The message every Gatekeeper refusal carries; the engine's own errors never do.
DENIED = re.compile(r"Gatekeeper denied this statement")


def enforce(connection):
    """Latch ``connection`` into enforcement; returns the posture warnings."""
    row = connection.execute("CALL gatekeeper_enforce()").fetchone()
    assert row[0] is True
    return row[1]


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
