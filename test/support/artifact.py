"""The repository, the loadable artifact under test, and connections with it loaded."""
import os
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[2]
EXTENSION = Path(os.getenv("GATEKEEPER_EXTENSION",
                           ROOT / "build/release/extension/gatekeeper/gatekeeper.duckdb_extension"))


def literal(text):
    """``text`` as a SQL string literal."""
    return "'" + str(text).replace("'", "''") + "'"


def connect(extension=EXTENSION, **config):
    """A fresh in-memory database with the artifact loaded; closed again if the load fails."""
    connection = duckdb.connect(config={"allow_unsigned_extensions": "true", **config})
    try:
        connection.execute("LOAD " + literal(extension))
    except Exception:
        connection.close()
        raise
    return connection
