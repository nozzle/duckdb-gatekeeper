"""Types are supplied by the host; executable type parameters still undergo preflight."""
import pytest

from test_gatekeeper import db
from typed_helpers import validate


@pytest.mark.parametrize("target", ["JSON", "STRUCT(j JSON[], n INTEGER)"])
def test_nested_host_types(db, target):
    assert validate(db, "SELECT NULL::" + target, {"allowed_tables": []})["allowed"]


@pytest.mark.parametrize("name", ["json", "inet", "point_2d", "integer"])
def test_same_name_host_types(db, name):
    db.execute(f"CREATE SCHEMA private; CREATE TYPE private.{name} AS ENUM ('secret'); SET search_path='private'")
    targets = [f'private."{name}"'] if name == "integer" else [name, f'private."{name}"']
    for target in targets:
        result = validate(db, f"SELECT NULL::{target}")
        assert result["allowed"], result


@pytest.mark.parametrize("sql", [
    "SELECT 1::DECIMAL(5 + 5, 2)",
    "SELECT NULL::STRUCT(v DECIMAL(5 + 5, 2))",
])
def test_type_parameter_expressions_remain_restricted(db, sql):
    result = validate(db, sql)
    # The pinned SQL parser rejects computed modifiers even before AST preflight.
    # Serializer-level preflight is covered in test_validator_structure.py.
    assert result["code"] == "parser" and not result["allowed"], result


def test_literal_type_parameters_and_casts(db):
    for sql in ("SELECT 1::DECIMAL(10, 2)", "SELECT '{\"n\":2}'::JSON::STRUCT(n INTEGER)"):
        assert validate(db, sql)["allowed"], validate(db, sql)
        db.execute(sql).fetchall()
