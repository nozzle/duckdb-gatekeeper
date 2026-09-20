"""The repository, the loadable artifact under test, and connections with it loaded.

The default location and the load idiom are scripts/artifact.py's; this module adds two environment overrides:
GATEKEEPER_EXTENSION, which the distribution workflow uses to point the suite at a downloaded platform
artifact, and GATEKEEPER_PARSER, which selects the SQL parser every connection the suite opens runs under.
"""
import os
from pathlib import Path

import artifact as loadable
from artifact import literal  # noqa: F401  (re-exported: tests build SQL with it)

ROOT = loadable.ROOT
EXTENSION = Path(os.getenv("GATEKEEPER_EXTENSION", loadable.DEFAULT_EXTENSION))

# The parser leg. "postgres" is the engine's default PostgreSQL-derived parser; "peg" opts every connection into
# the autocomplete extension's PEG parser override (DuckDB 1.5's experimental parser, the default from 2.0).
# Gatekeeper parses with the connection's ParserOptions, so its decisions must agree with the engine under
# either; the two parsers do differ in what they stamp on the AST (query locations, arity of keyword-named
# calls) and in which stage reports max_expression_depth, so a few diagnostics are parser-specific.
PARSERS = ("postgres", "peg")
PARSER = os.getenv("GATEKEEPER_PARSER", PARSERS[0])
if PARSER not in PARSERS:
    raise ValueError(f"GATEKEEPER_PARSER must be one of {PARSERS}, not {PARSER!r}")
PARSER_OVERRIDE_SETTING = "allow_parser_override_extension"


def by_parser(**expectation):
    """The value for the parser under test, given one keyword per parser (``by_parser(postgres=17, peg=7)``)."""
    if set(expectation) != set(PARSERS):
        raise ValueError(f"expected one value per parser {PARSERS}, got {sorted(expectation)}")
    return expectation[PARSER]


def enable_peg_parser(connection):
    """Route ``connection``'s database through the PEG parser: load autocomplete and make its override strict,
    so a statement it cannot parse is an error rather than a silent fallback to the default parser."""
    connection.execute("LOAD autocomplete")
    connection.execute("CALL enable_peg_parser()")


def connect(extension=EXTENSION, **config):
    """A fresh in-memory database with the artifact under test loaded and the selected parser in force; closed
    again if either step fails."""
    connection = loadable.connect(extension, **config)
    if PARSER == "peg":
        try:
            enable_peg_parser(connection)
        except Exception:
            connection.close()
            raise
    return connection
