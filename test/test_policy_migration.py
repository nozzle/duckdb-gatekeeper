"""Legacy shapes have one actionable diagnostic across the policy input decoders."""
import json
import re

import duckdb
import pytest

from support.typed_helpers import configure, policy, validate


OPTIONS = ["allowed_functions", "blocked_functions", "allowed_tables", "blocked_tables"]


def migration(option):
    shape = "{catalog?, schema_path, name, type?}" if "functions" in option else "{catalog?, schema_path, table}"
    return (f"{option}: legacy rule shape is unsupported; migrate to policy v2 {shape} rules; "
            "schema_path is a nonempty list of schema components")


def encodings(option, entries):
    options = {option: entries}
    return [options, {"json": json.dumps({"version": 2, "options": options})}]


@pytest.mark.parametrize("option", OPTIONS)
@pytest.mark.parametrize("canonical_path", [False, True])
def test_schema_field_migration_matches_typed_and_json(db, option, canonical_path):
    leaf = "name" if "functions" in option else "table"
    entry = {"schema": "x", leaf: "abs" if leaf == "name" else "y"}
    if canonical_path:
        entry["schema_path"] = ["x"]
    before = policy(db)
    for arguments in encodings(option, [entry]):
        result = validate(db, "SELECT 1", arguments)
        assert result["code"] == "invalid_input" and not result["allowed"]
        assert result["error_message"] == migration(option)
        with pytest.raises(duckdb.BinderException, match=re.escape(migration(option))):
            configure(db, arguments)
        assert policy(db) == before


@pytest.mark.parametrize("option", ["allowed_functions", "blocked_functions"])
def test_string_function_lists_name_the_actual_option_and_replacement(db, option):
    before = policy(db)
    for operation in [lambda: validate(db, "SELECT 1", {option: ["abs"]}),
                      lambda: configure(db, {option: ["abs"]})]:
        with pytest.raises(duckdb.BinderException, match=re.escape(migration(option))):
            operation()
    arguments = encodings(option, ["abs"])[1]
    assert validate(db, "SELECT 1", arguments)["error_message"] == migration(option)
    with pytest.raises(duckdb.BinderException, match=re.escape(migration(option))):
        configure(db, arguments)
    assert policy(db) == before


@pytest.mark.parametrize("option", OPTIONS)
@pytest.mark.parametrize("field,expected", [
    ("schema VARCHAR", "migration"),
    ("schema_path VARCHAR[], extra VARCHAR", "unknown"),
    ("catalog VARCHAR", "required"),
])
def test_empty_typed_struct_lists_still_validate_declared_fields(db, option, field, expected):
    functions = "functions" in option
    leaf, rule = ("name", "function") if functions else ("table", "table")
    expression = f'[]::STRUCT({field}, "{leaf}" VARCHAR)[]'
    message = {"migration": migration(option),
               "unknown": f"{option}: unknown {rule} rule field: extra",
               "required": f"{option}: {rule} rules require schema_path and {leaf}"}[expected]
    result = db.execute(f"SELECT code, error_message FROM gatekeeper_validate('SELECT 1', {option} := {expression})").fetchone()
    assert result == ("invalid_input", message)
    before = policy(db)
    with pytest.raises(duckdb.BinderException, match=re.escape(message)):
        db.execute(f"CALL gatekeeper_configure({option} := {expression})")
    assert policy(db) == before


@pytest.mark.parametrize("option", ["allowed_functions", "blocked_functions"])
def test_empty_typed_string_lists_require_migration_but_untyped_empty_is_valid(db, option):
    for prefix in ["CALL gatekeeper_configure(", "SELECT * FROM gatekeeper_validate('SELECT 1', "]:
        with pytest.raises(duckdb.BinderException, match=re.escape(migration(option))):
            db.execute(prefix + f"{option} := []::VARCHAR[])")
    for arguments in encodings(option, []):
        assert validate(db, "SELECT 1", arguments)["allowed"]
        assert configure(db, arguments)
        assert policy(db)[option] == []


@pytest.mark.parametrize("option", OPTIONS)
def test_unrelated_unknown_fields_are_rule_errors_not_migration(db, option):
    leaf, rule = ("name", "function") if "functions" in option else ("table", "table")
    message = f"{option}: unknown {rule} rule field: extra"
    for arguments in encodings(option, [{"schema_path": ["x"], leaf: "y", "extra": "z"}]):
        assert validate(db, "SELECT 1", arguments)["error_message"] == message
        with pytest.raises(duckdb.BinderException, match=re.escape(message)):
            configure(db, arguments)


@pytest.mark.parametrize("option", ["allowed_functions", "blocked_functions"])
def test_function_name_is_required_not_an_implicit_schema_wildcard(db, option):
    message = f"{option}: function rules require schema_path and name"
    for arguments in encodings(option, [{"schema_path": ["main"]}]):
        assert validate(db, "SELECT 1", arguments)["error_message"] == message
        with pytest.raises(duckdb.BinderException, match=re.escape(message)):
            configure(db, arguments)
    # '*' names the multiplication operator; it never grants all functions in a schema.
    options = {"use_default_functions": False,
               "allowed_functions": [{"schema_path": ["main"], "name": "*"}]}
    assert not validate(db, "SELECT abs(1)", options)["allowed"]


@pytest.mark.parametrize("option", ["allowed_functions", "blocked_functions"])
@pytest.mark.parametrize("field,value", [
    ("name", None), ("name", ""), ("name", "a\0b"),
    ("schema_path", None), ("schema_path", []), ("schema_path", [None]),
    ("schema_path", [""]), ("schema_path", ["a\0b"]),
])
def test_v2_function_fields_remain_strict(db, option, field, value):
    entry = {"schema_path": ["main"], "name": "abs", "type": None, field: value}
    before = policy(db)
    for arguments in encodings(option, [entry]):
        result = validate(db, "SELECT 1", arguments)
        assert result["code"] == "invalid_input" and not result["allowed"]
        assert "legacy" not in result["error_message"]
        with pytest.raises(duckdb.BinderException):
            configure(db, arguments)
        assert policy(db) == before


@pytest.mark.parametrize("option", ["allowed_functions", "blocked_functions"])
def test_optional_null_type_and_catalog_round_trip_without_weakening_canonical_checks(db, option):
    entry = {"catalog": None, "schema_path": ["MAIN"], "name": "ABS", "type": None}
    for arguments in encodings(option, [entry]):
        assert validate(db, "SELECT 1", arguments)["allowed"]
        assert configure(db, arguments)
        before = policy(db)
        assert before[option] == [{"catalog": "", "schema_path": ["main"], "name": "abs", "type": ""}]
        db.execute("SET gatekeeper_policy = current_setting('gatekeeper_policy')")
        assert policy(db) == before
        for field in ["catalog", "schema_path", "name", "type"]:
            fields = {"catalog": "''", "schema_path": "['main']", "name": "'abs'", "type": "''"}
            fields[field] = "NULL"
            struct = "{" + ", ".join(f"{key}: {value}" for key, value in fields.items()) + "}"
            with pytest.raises(duckdb.Error, match=re.escape(f"NULL policy field: {option}.{field}")):
                db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), "
                           f"{option} := [{struct}])")
            assert policy(db) == before


@pytest.mark.parametrize("option", OPTIONS)
def test_set_cast_of_legacy_schema_cannot_bypass_canonical_integrity(db, option):
    leaf = "name" if "functions" in option else "table"
    optional_type = ", type: ''" if "functions" in option else ""
    before = policy(db)
    # SET's engine cast erases schema before ReadPolicy sees it. Diagnose the resulting
    # canonical NULL, rather than claiming to recognize a legacy field no longer present.
    with pytest.raises(duckdb.Error, match=re.escape(f"NULL policy field: {option}.schema_path")):
        db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), "
                   f"{option} := [{{catalog: '', schema: 'x', '{leaf}': 'y'{optional_type}}}])")
    assert policy(db) == before
