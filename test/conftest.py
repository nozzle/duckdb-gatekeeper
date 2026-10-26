"""Fixtures shared across the suite. Functions and constants live in test/support; import them from there."""
import pytest

from support.artifact import ENGINE_MAJOR, PARSER, PARSER_OVERRIDE_SETTING, connect
from support.corpus import CATALOG_POLICY, CATALOG_SQL
from support.enforcement import enforce
from support.typed_helpers import configure


def pytest_report_header(config):
    return f"gatekeeper parser leg: {PARSER} (DuckDB {ENGINE_MAJOR}.x)"


@pytest.fixture(scope="session", autouse=True)
def parser_leg():
    """Prove the requested parser is active, including both engines' extension-based alternatives."""
    if PARSER == "peg" and ENGINE_MAJOR < 2:
        with connect() as connection:
            mode = connection.execute(f"SELECT current_setting('{PARSER_OVERRIDE_SETTING}')").fetchone()[0]
            assert mode == "strict", mode
    elif ENGINE_MAJOR >= 2:
        with connect() as connection:
            if PARSER == "postgres":
                assert connection.execute("SELECT current_setting('enable_legacy_parser')").fetchone() == (True,)
            # These intentional parser differences make a silent fallback observable.
            assert connection.execute("SELECT 'abc' ~ 'b', 2 * 3!").fetchone() == (
                (True, 12) if PARSER == "peg" else (False, 720))


@pytest.fixture
def db():
    """A fresh in-memory database with the artifact loaded and the default policy."""
    with connect() as connection:
        yield connection


@pytest.fixture
def catalog(db):
    """The reporting/secret catalog under CATALOG_POLICY; the host connection of the parity legs."""
    db.execute(CATALOG_SQL)
    configure(db, CATALOG_POLICY)
    return db


@pytest.fixture
def agent(catalog):
    """An enforced cursor on the catalog's database."""
    with catalog.cursor() as cursor:
        enforce(cursor)
        yield cursor
