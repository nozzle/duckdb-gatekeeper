import json

import pytest

from test_gatekeeper import ROOT, db
from typed_helpers import validate, configure, never_bind_names


@pytest.fixture
def expressions(db):
    db.execute("""CREATE TABLE t AS SELECT '{"a":1}'::JSON j, [1,2] arr,
               {'a': 1} st, map(['a'], [1]) m, 1::VARIANT v, 1 x,
               2 AS current_schema; CREATE MACRO trusted_abs(x) AS abs(x)""")
    return db


@pytest.mark.parametrize("sql,name", [
    ("SELECT j->'a' FROM t", "json_extract"), ("SELECT j->>'a' FROM t", "json_extract_string"),
    ("SELECT st.a FROM t", "struct_extract"), ("SELECT arr[1] FROM t", "array_extract"),
    ("SELECT m['a'] FROM t", "map_extract_value"), ("SELECT v['a'] FROM t", "variant_extract"),
    ("SELECT arr[1:2] FROM t", "array_slice"), ("SELECT [1,2]", "list_value"),
    ("SELECT current_catalog", "current_catalog"), ("SELECT current_schema", "current_schema"),
    ("SELECT current_user", "current_user"), ("SELECT current_date", "current_date"),
    ("SELECT session_user", "session_user"), ("SELECT localtime", "current_localtime"),
])
def test_synthesized_functions_obey_blocks_and_allowlist(expressions, sql, name):
    for options in [{"blocked_functions": [name]}, {"check_functions": False, "blocked_functions": [name]},
                    {"use_default_functions": False}]:
        result = validate(expressions, sql, options)
        assert result["code"] == "forbidden" and result["error_message"] == "", result
        assert any(v["rule"] == "function" and v["function_name"] == name for v in result["violations"]), result


def test_resolution_does_not_confuse_columns_with_functions(expressions):
    options = {"use_default_functions": False, "blocked_functions": ["struct_extract", "current_schema"]}
    assert validate(expressions, "SELECT t.x, current_schema FROM t", options)["allowed"]
    assert validate(expressions, "SELECT arr[1] FROM t", {"allowed_functions": ["array_extract"],
                                                        "use_default_functions": False})["allowed"]
    assert validate(expressions, "SELECT st.a FROM t", {"allowed_functions": ["struct_extract"],
                                                      "use_default_functions": False})["allowed"]


def test_variant_requires_explicit_function_permission(expressions):
    result = validate(expressions, "SELECT v['a'] FROM t")
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "variant_extract"
    configure(expressions, {"allowed_functions": ["variant_extract"]})
    assert validate(expressions, "SELECT v['a'] FROM t", {"allowed_functions": ["variant_extract"]})["allowed"]


def test_blocks_apply_in_trusted_expansions(expressions, tmp_path):
    configure(expressions, {"allowed_functions": ["trusted_abs"]})
    assert validate(expressions, "SELECT trusted_abs(-1)", {"allowed_functions": ["trusted_abs"]})["allowed"]
    assert not validate(expressions, "SELECT trusted_abs(-1)", {
        "allowed_functions": ["trusted_abs"], "blocked_functions": ["abs"]})["allowed"]
    path = str(tmp_path / "trusted.parquet").replace("'", "''")
    expressions.execute(f"COPY (SELECT 1 x) TO '{path}' (FORMAT PARQUET)")
    expressions.execute(f"CREATE VIEW file_view AS SELECT * FROM read_parquet('{path}')")
    options = {"allowed_tables": [{"schema": "main", "table": "file_view"}]}
    assert validate(expressions, "SELECT * FROM file_view", options)["allowed"]
    result = validate(expressions, "SELECT * FROM file_view", {**options, "blocked_functions": ["read_parquet"]})
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "read_parquet"


def test_never_bind_names_absent_from_defaults_and_non_overridable(db):
    names = never_bind_names()
    for name in names:
        for options in [{"allowed_functions": [name]}, {"check_functions": False}]:
            result = validate(db, f'SELECT "{name}"(1)', options)
            assert result["code"] == "forbidden" and result["error_message"] == "", (name, result)


@pytest.mark.parametrize("typ", ["INET", "JSON", "private_schema.no_such_type", "STRUCT(x INTEGER, y INET[])",
                                 "MAP(VARCHAR, INET)", "UNION(x INTEGER, y INET)"])
def test_type_preflight_blocks_before_lookup(db, typ):
    result = validate(db, "SELECT NULL::" + typ)
    assert result["code"] == "forbidden" and result["error_message"] == "", result
    assert any(v["rule"] == "type" for v in result["violations"])


@pytest.mark.parametrize("typ", ["INTEGER", "DECIMAL(10,2)", "STRUCT(x INTEGER, y VARCHAR[])",
                                 "MAP(VARCHAR, INTEGER)", "INTEGER[3]", "UNION(x INTEGER, y VARCHAR)",
                                 'STRUCT("collation" INTEGER)', 'UNION("collation" INTEGER, b VARCHAR)'])
def test_builtin_nested_types(db, typ):
    result = validate(db, "SELECT NULL::" + typ)
    assert result["allowed"], result


def test_allowed_types_resolve_identity_and_inherit(db):
    db.execute("CREATE SCHEMA Reporting; CREATE TYPE Reporting.Customer AS ENUM ('a','b'); SET search_path='Reporting'")
    permission = {"catalog": "MeMoRy", "schema": "REPORTING", "type": "CUSTOMER"}
    assert not validate(db, "SELECT 'a'::Customer", {"allowed_types": [permission]})["allowed"]
    configure(db, {"allowed_types": [permission]})
    assert validate(db, "SELECT 'a'::Customer", {"allowed_types": [permission]})["allowed"]
    assert not validate(db, "SELECT 'a'::Customer", {
        "allowed_types": [{"schema": "wrong", "type": "Customer"}]})["allowed"]
    configure(db, {"allowed_types": [permission]})
    assert validate(db, "SELECT 'a'::Customer")["allowed"]
    assert not validate(db, "SELECT 'a'::Customer", {"allowed_types": []})["allowed"]


@pytest.mark.parametrize("entries", [None, [None], [{"type": "foo"}], [{"schema": "main", "type": None}],
                                      [{"schema": "main", "type": "foo", "extra": "x"}]])
def test_allowed_types_invalid_values(db, entries):
    result = validate(db, "SELECT 1", {"allowed_types": entries})
    assert result["code"] == "invalid_input", result


@pytest.mark.parametrize("name", ["nocase", "noaccent", "nfc", "binary"])
def test_builtin_collations_obey_explicit_blocks(db, name):
    sql = f"SELECT 'a' COLLATE \"{name}\""
    assert validate(db, sql)["allowed"]
    result = validate(db, sql, {"blocked_functions": [name]})
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == name


def test_nondefault_collation_requires_explicit_permission(db):
    result = validate(db, "SELECT 'a' COLLATE de")
    assert result["code"] == "forbidden" and result["error_message"] == ""
    configure(db, {"allowed_functions": ["de"]})
    assert validate(db, "SELECT 'a' COLLATE de", {"allowed_functions": ["de"]})["allowed"]


@pytest.mark.parametrize("collation,function", [("nocase", "lower"), ("noaccent", "strip_accents"), ("nfc", "nfc_normalize")])
def test_collation_implementation_blocks_before_binding(db, collation, function):
    result = validate(db, f"SELECT 'a' COLLATE {collation}", {"blocked_functions": [function]})
    assert result["code"] == "forbidden" and result["error_message"] == "", result


def test_type_permission_does_not_allow_shadowing_builtin(db):
    db.execute("CREATE SCHEMA custom; CREATE TYPE custom.integer AS VARCHAR; SET search_path='custom'")
    result = validate(db, 'SELECT \'a\'::custom."integer"')
    assert not result["allowed"] and result["violations"][0]["rule"] == "type", result


def test_json_type_explicit_permission(db):
    configure(db, {"allowed_types": [{"catalog": "system", "schema": "main", "type": "json"}]})
    result = validate(db, "SELECT '{}'::JSON", {"allowed_types": [{"catalog": "system", "schema": "main", "type": "json"}]})
    assert result["allowed"], result


def test_pivot_and_window_blocks(expressions):
    for sql in ["SELECT sum(x) OVER () FROM t", "PIVOT t ON x IN (1) USING sum(x)"]:
        result = validate(expressions, sql, {"blocked_functions": ["sum"]})
        assert result["code"] == "forbidden" and result["error_message"] == "", result


def test_named_pivot_enum_is_conservatively_rejected(db):
    db.execute("CREATE TYPE pivot_values AS ENUM ('a'); CREATE TABLE p(k VARCHAR, x INTEGER)")
    result = validate(db, "PIVOT p ON k IN pivot_values USING sum(x)")
    assert result["code"] == "unsupported" and result["error_message"] == "", result


def test_conservative_synthesis_overlap_with_trusted_macro(expressions):
    expressions.execute("CREATE MACRO hidden_extract(x) AS struct_extract(x, 'a')")
    options = {"use_default_functions": False, "allowed_functions": ["hidden_extract"]}
    configure(expressions, {"allowed_functions": ["hidden_extract"]})
    assert validate(expressions, "SELECT hidden_extract(st) FROM t", options)["allowed"]
    # The callback has no expression provenance: a qualified caller column marks
    # struct extraction as a possible implementation, including trusted expansions.
    result = validate(expressions, "SELECT t.x, hidden_extract(st) FROM t", options)
    assert result["code"] == "forbidden", result


def test_default_non_compute_value_functions_require_opt_in(db):
    for name in ["current_schema", "current_catalog", "current_user", "current_date"]:
        result = validate(db, "SELECT " + name)
        assert result["code"] == "forbidden", (name, result)
        configure(db, {"allowed_functions": [name]})
        assert validate(db, "SELECT " + name, {"allowed_functions": [name]})["allowed"]
        configure(db)


def test_type_denial_does_not_autoload_inet(db):
    before = db.execute("SELECT loaded FROM duckdb_extensions() WHERE extension_name='inet'").fetchone()
    assert before == (False,)
    result = validate(db, "SELECT '127.0.0.1'::INET")
    assert result["code"] == "forbidden" and result["error_message"] == ""
    assert db.execute("SELECT loaded FROM duckdb_extensions() WHERE extension_name='inet'").fetchone() == before


def test_whole_row_reference_requires_struct_pack(expressions):
    assert not validate(expressions, "SELECT t FROM t", {"use_default_functions": False})["allowed"]
    assert validate(expressions, "SELECT t FROM t", {
        "use_default_functions": False, "allowed_functions": ["struct_pack"]})["allowed"]


def test_function_child_arrow_can_still_be_json(expressions):
    options = {"use_default_functions": False, "allowed_functions": ["coalesce"]}
    result = validate(expressions, "SELECT coalesce(j->'a', j) FROM t", options)
    assert result["code"] == "forbidden"
    assert any(v["function_name"] == "json_extract" for v in result["violations"])
    assert validate(expressions, "SELECT j->>'a' FROM t", {
        "use_default_functions": False, "allowed_functions": ["json_extract_string"]})["allowed"]


def test_legacy_lambda_overlap_and_keyword_workaround(expressions):
    expressions.execute("SET lambda_syntax='ENABLE_SINGLE_ARROW'; CREATE VIEW v_json AS SELECT json_extract(j, 'a') z FROM t")
    options = {"use_default_functions": False, "allowed_functions": ["list_transform", "+"]}
    sql = "SELECT list_transform(arr, x -> x + 1), z FROM t, v_json"
    assert not validate(expressions, sql, options)["allowed"]
    assert validate(expressions, sql.replace("x ->", "lambda x:"), options)["allowed"]


@pytest.mark.parametrize("name", ["row_number", "rank", "dense_rank"])
def test_nonaggregate_windows_in_trusted_view(db, name):
    db.execute(f"CREATE VIEW w AS SELECT {name}() OVER () n")
    assert validate(db, "SELECT * FROM w")["allowed"]
    result = validate(db, "SELECT * FROM w", {"blocked_functions": [name]})
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == name


def test_allowed_types_intersect_namespace_policy(db):
    db.execute("CREATE SCHEMA private; CREATE TYPE private.customer AS ENUM ('a')")
    options = {"allowed_types": [{"schema": "private", "type": "customer"}]}
    configure(db, options)
    assert validate(db, "SELECT 'a'::private.customer", options)["allowed"]
    assert not validate(db, "SELECT 'a'::private.customer", {**options, "allowed_schemas": ["public"]})["allowed"]
    options = {"allowed_types": [{"schema": "main", "type": "json"}], "allowed_catalogs": ["memory"]}
    assert not validate(db, "SELECT '{}'::JSON", options)["allowed"]
    # Builtins are namespace-independent; adding a cast does not require system catalog access.
    assert validate(db, "SELECT 1::INTEGER", {"allowed_catalogs": [], "allowed_schemas": []})["allowed"]


def test_collation_permission_remains_separate_capability(db):
    result = validate(db, "SELECT 'a' COLLATE de", {"check_functions": False})
    assert result["code"] == "forbidden"
    # Function allowlist options cannot be supplied while function checks are disabled.
    result = validate(db, "SELECT 'a' COLLATE de", {"check_functions": False, "allowed_functions": ["de"]})
    assert result["code"] == "invalid_input"
