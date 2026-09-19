"""Fixtures shared across the suite. Functions and constants live in test/support; import them from there."""
import pytest

from support.artifact import connect
from support.corpus import CATALOG_POLICY, CATALOG_SQL
from support.enforcement import enforce
from support.typed_helpers import configure


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
