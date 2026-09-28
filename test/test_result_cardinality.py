"""Every output vector is a one-row vector, including empty/nonempty nested values (#102)."""
import pytest

from support.typed_helpers import validate


@pytest.mark.parametrize("projection, expected", [
    ("enforced, warnings IS NOT NULL", (True, True)),
    ("enforced, warnings IS NULL", (True, False)),
    ("enforced AND warnings IS NOT NULL", (True,)),
    ("warnings IS NOT NULL, enforced, warnings IS NOT NULL", (True, True, True)),
    ("enforced::INTEGER + (warnings IS NOT NULL)::INTEGER", (2,)),
    ("(warnings IS NOT NULL)::INTEGER + enforced::INTEGER", (2,)),
    ("enforced, list_count(warnings) = len(warnings)", (True, True)),
])
@pytest.mark.parametrize("empty_warnings", [False, True])
def test_enforce_projection_on_fresh_connection(db, projection, expected, empty_warnings):
    if empty_warnings:
        db.execute("CALL enable_logging('Gatekeeper')")
        db.execute("SET enable_external_access=false; SET autoload_known_extensions=false; "
                   "SET autoinstall_known_extensions=false; SET lock_configuration=true")
    assert db.execute(f"SELECT {projection} FROM gatekeeper_enforce()").fetchall() == [expected]
    assert db.execute("SELECT 42").fetchall() == [(42,)]


def test_enforce_filtered_row(db):
    rows = db.execute("SELECT * FROM gatekeeper_enforce() WHERE enforced AND warnings IS NOT NULL").fetchall()
    assert len(rows) == 1 and rows[0][0] is True and isinstance(rows[0][1], list)
    assert db.execute("SELECT 42").fetchone() == (42,)


@pytest.mark.parametrize("sql", ["SELECT 1", "SELECT md5('a')", "DROP TABLE t", "SELECT FROM"])
def test_validation_nested_projection(db, sql):
    expected = validate(db, sql)
    fields = ["violations", "objects", "functions", "caller_objects", "caller_functions"]
    projection = ", ".join(f"{field} IS NOT NULL, allowed OR {field} IS NULL" for field in fields)
    row = db.execute(f"SELECT allowed, {projection} FROM gatekeeper_validate(?)", [sql]).fetchone()
    assert row == (expected["allowed"], *[v for _ in fields for v in (True, expected["allowed"])])


def test_configure_boolean_projection(db):
    # Configuration, validation and enforcement share the result-row writer.
    assert db.execute("SELECT success, success IS NOT NULL FROM gatekeeper_configure()").fetchall() == [(True, True)]
