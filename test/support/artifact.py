"""The repository, the loadable artifact under test, and connections with it loaded.

The default location and the load idiom are scripts/artifact.py's; this module adds two environment overrides:
GATEKEEPER_EXTENSION, which the distribution workflow uses to point the suite at a downloaded platform
artifact, and GATEKEEPER_PARSER, which selects the SQL parser in force on every connection the suite opens here.
The raw duckdb.connect() calls in test_versions.py exist to test the artifact's own load path and apply the
selection with select_parser() once the artifact is loaded; those in test_typed_api.py never load Gatekeeper.
"""
import os
from pathlib import Path

import duckdb

import artifact as loadable
from artifact import literal  # noqa: F401  (re-exported: tests build SQL with it)

ROOT = loadable.ROOT
EXTENSION = Path(os.getenv("GATEKEEPER_EXTENSION", loadable.DEFAULT_EXTENSION))
# The engine source the artifact was built from, for the tests that compile against its headers or generate the
# grammar from its serialization schema: the pinned submodule, or another checkout (a 2.0 candidate) when
# GATEKEEPER_ENGINE_SOURCE names one alongside GATEKEEPER_EXTENSION.
ENGINE_SOURCE = Path(os.getenv("GATEKEEPER_ENGINE_SOURCE", str(ROOT / "duckdb")))

# The major version of the engine the suite runs in (the duckdb Python package). Engine behavior the tests
# pin differs between DuckDB 1.5 and 2.0; see by_engine().
ENGINE_MAJOR = int(duckdb.__version__.split(".")[0])

# The parser leg. "postgres" is DuckDB 1.5's default PostgreSQL-derived parser; "peg" is the PEG parser: under
# 1.5 the autocomplete extension's override, which the leg opts every connection into, and from 2.0 the only
# parser there is, so 2.0 has one leg. Gatekeeper parses with the connection's ParserOptions, so its decisions
# must agree with the engine under either; the two parsers do differ in what they stamp on the AST (query
# locations, arity of keyword-named calls) and in which stage reports max_expression_depth, so a few
# diagnostics are parser-specific.
PARSERS = ("postgres", "peg")
PARSER = os.getenv("GATEKEEPER_PARSER", PARSERS[0] if ENGINE_MAJOR < 2 else "peg")
if PARSER not in PARSERS:
    raise ValueError(f"GATEKEEPER_PARSER must be one of {PARSERS}, not {PARSER!r}")
if ENGINE_MAJOR >= 2 and PARSER != "peg":
    raise ValueError(f"DuckDB {duckdb.__version__} has only the PEG parser; GATEKEEPER_PARSER={PARSER!r} cannot run")
PARSER_OVERRIDE_SETTING = "allow_parser_override_extension"


def by_parser(**expectation):
    """The value for the parser under test, given one keyword per parser (``by_parser(postgres=17, peg=7)``)."""
    if set(expectation) != set(PARSERS):
        raise ValueError(f"expected one value per parser {PARSERS}, got {sorted(expectation)}")
    return expectation[PARSER]


def by_engine(**expectation):
    """The value for the engine release line under test, given one keyword per line (``by_engine(v1=..., v2=...)``):
    for engine behavior a test pins that DuckDB changed between 1.5 and 2.0, such as which statements its parser
    accepts or whether an error aborts an open transaction. Gatekeeper's own decisions are the same on both."""
    if set(expectation) != {"v1", "v2"}:
        raise ValueError(f"expected v1 and v2, got {sorted(expectation)}")
    return expectation["v1" if ENGINE_MAJOR < 2 else "v2"]


def enable_peg_parser(connection):
    """Route ``connection``'s database through the PEG parser. Under DuckDB 1.5 that is the autocomplete
    extension's override, made strict so a statement it cannot parse is an error rather than a silent fallback
    to the default parser; from 2.0 the PEG parser is the engine's only parser and there is nothing to enable."""
    if ENGINE_MAJOR >= 2:
        return
    connection.execute("LOAD autocomplete")
    connection.execute("CALL enable_peg_parser()")


def select_parser(connection):
    """Put the selected parser in force on ``connection``'s database; nothing to do for the engine's default."""
    if PARSER == "peg":
        enable_peg_parser(connection)


def connect(extension=EXTENSION, **config):
    """A fresh in-memory database with the artifact under test loaded and the selected parser in force; closed
    again if either step fails."""
    connection = loadable.connect(extension, **config)
    try:
        select_parser(connection)
    except Exception:
        connection.close()
        raise
    return connection
