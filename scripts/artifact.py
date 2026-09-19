"""The loadable artifact: where a default build puts it and how a connection loads it.

This module imports duckdb. Nothing on the generation path (versions, inventory, schema_check, generate), which
runs at CMake configure time with a standard-library-only interpreter, may import it.
"""
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
# Where scripts/build.py puts the loadable; every script and test that takes an artifact defaults to it.
DEFAULT_EXTENSION = ROOT / "build/release/extension/gatekeeper/gatekeeper.duckdb_extension"


def literal(text):
    """``text`` as a SQL string literal."""
    return "'" + str(text).replace("'", "''") + "'"


def load(connection, extension):
    """LOAD the extension file at ``extension`` into ``connection``."""
    connection.execute("LOAD " + literal(Path(extension).resolve()))


def connect(extension=DEFAULT_EXTENSION, **config):
    """A fresh in-memory database with the artifact loaded and unsigned loading allowed; closed again if the
    load fails. Further ``config`` entries are DuckDB configuration options, applied before the load."""
    connection = duckdb.connect(config={"allow_unsigned_extensions": "true", **config})
    try:
        load(connection, extension)
    except Exception:
        connection.close()
        raise
    return connection
