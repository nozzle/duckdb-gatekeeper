import pytest

from support.headers import never_bind_names
from support.typed_helpers import configure, validate


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
    for options in [{"blocked_functions": [name]}, {"allowed_functions": [name], "blocked_functions": [name]},
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


def test_variant_indexing_resolves_to_variant_extract(expressions):
    # v['a'] on a VARIANT synthesizes variant_extract, a reviewed default; the synthesized name
    # still answers to blocks, to defaults being disabled, and to an explicit grant.
    assert validate(expressions, "SELECT v['a'] FROM t")["allowed"]
    for options in [{"blocked_functions": ["variant_extract"]}, {"use_default_functions": False}]:
        result = validate(expressions, "SELECT v['a'] FROM t", options)
        assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "variant_extract", result
    configure(expressions, {"use_default_functions": False, "allowed_functions": ["variant_extract"]})
    assert validate(expressions, "SELECT v['a'] FROM t", {"allowed_functions": ["variant_extract"]})["allowed"]
    configure(expressions)


def test_blocks_do_not_reach_into_trusted_expansions(expressions, tmp_path):
    # What a host macro or view uses is that definition's own; blocks govern what the caller writes and the
    # implementations it binds, and a caller-written use next to the definition is still the caller's.
    configure(expressions, {"allowed_functions": ["trusted_abs"]})
    assert validate(expressions, "SELECT trusted_abs(-1)", {"allowed_functions": ["trusted_abs"]})["allowed"]
    assert validate(expressions, "SELECT trusted_abs(-1)", {
        "allowed_functions": ["trusted_abs"], "blocked_functions": ["abs"]})["allowed"]
    assert not validate(expressions, "SELECT trusted_abs(-1) + abs(-2)", {
        "allowed_functions": ["trusted_abs"], "blocked_functions": ["abs"]})["allowed"]
    path = str(tmp_path / "trusted.parquet").replace("'", "''")
    expressions.execute(f"COPY (SELECT 1 x) TO '{path}' (FORMAT PARQUET)")
    expressions.execute(f"CREATE VIEW file_view AS SELECT * FROM read_parquet('{path}')")
    options = {"allowed_tables": [{"schema": "main", "table": "file_view"}]}
    assert validate(expressions, "SELECT * FROM file_view", options)["allowed"]
    result = validate(expressions, "SELECT * FROM file_view", {**options, "blocked_functions": ["read_parquet"]})
    assert result["allowed"] and any(f["name"] == "read_parquet" for f in result["functions"]), result
    result = validate(expressions, f"SELECT * FROM file_view, read_parquet('{path}')",
                      {**options, "allowed_functions": ["read_parquet"], "blocked_functions": ["read_parquet"]})
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "read_parquet"


# Written out rather than read from the header: dropping a name from NeverBindFunctions() must fail here instead
# of silently shrinking the header-derived test below. One or more from each group docs/security.md reviews.
NEVER_BIND = ["query", "query_table", "json_execute_serialized_sql", "json_serialize_plan",  # dynamic SQL
              "read_duckdb", "seq_scan", "which_secret",  # hidden attach, internal scan, secrets
              "checkpoint", "force_checkpoint", "nextval", "currval",  # storage and sequence state
              "duckdb_settings", "duckdb_tables", "duckdb_secrets", "duckdb_logs", "pragma_table_info",  # metadata
              "enable_logging", "disable_logging", "truncate_duckdb_logs", "write_log",  # the log's lifecycle
              "gatekeeper_configure", "gatekeeper_enforce"]  # the policy


def never_bind_holds(db, name):
    for options in [{"allowed_functions": [name]}, {"use_default_functions": False, "allowed_functions": [name]}]:
        configure(db, options)
        result = validate(db, f'SELECT "{name}"(1)', options)
        assert result["code"] == "forbidden" and result["error_message"] == "", (name, result)


def test_written_never_bind_names_stay_denied(db):
    for name in NEVER_BIND:
        never_bind_holds(db, name)


def test_never_bind_names_absent_from_defaults_and_non_overridable(db):
    names = never_bind_names()
    assert set(NEVER_BIND) <= names
    for name in names:
        never_bind_holds(db, name)


def test_missing_type_returns_binding_error(db):
    result = validate(db, "SELECT NULL::main.no_such_type")
    assert result["code"] == "binding" and result["violations"] == [], result


@pytest.mark.parametrize("typ", ["INTEGER", "DECIMAL(10,2)", "STRUCT(x INTEGER, y VARCHAR[])",
                                 "MAP(VARCHAR, INTEGER)", "INTEGER[3]", "UNION(x INTEGER, y VARCHAR)",
                                 'STRUCT("collation" INTEGER)', 'UNION("collation" INTEGER, b VARCHAR)'])
def test_builtin_nested_types(db, typ):
    result = validate(db, "SELECT NULL::" + typ)
    assert result["allowed"], result


def test_user_types_use_connection_search_path(db):
    db.execute("CREATE SCHEMA Reporting; CREATE TYPE Reporting.Customer AS ENUM ('a','b'); SET search_path='Reporting'")
    assert validate(db, "SELECT 'a'::Customer")["allowed"]
    assert db.execute("SELECT 'a'::Customer").fetchone() == ('a',)


@pytest.mark.parametrize("name", ["nocase", "noaccent", "nfc", "binary", "de", "nocase.noaccent"])
def test_collations_need_no_name_permission(db, name):
    sql = f"SELECT 'a' COLLATE \"{name}\""
    assert validate(db, sql)["allowed"]
    result = validate(db, sql, {"blocked_functions": [name]})
    assert result["allowed"], result
    assert validate(db, sql, {"use_default_functions": False})["allowed"]


def test_host_collations_in_comparisons_sorting_and_types(db):
    db.execute("CREATE TABLE collated(s VARCHAR COLLATE de); INSERT INTO collated VALUES ('b'), ('a')")
    for sql in ("SELECT s FROM collated ORDER BY s COLLATE de",
                "SELECT s = 'a' COLLATE de FROM collated",
                "SELECT CAST(s AS VARCHAR) COLLATE de FROM collated"):
        assert validate(db, sql, {"use_default_functions": False})["allowed"], validate(db, sql)
        db.execute(sql).fetchall()


@pytest.mark.parametrize("collation,function", [("nocase", "lower"), ("noaccent", "strip_accents"), ("nfc", "nfc_normalize")])
def test_collation_does_not_infer_function_call(db, collation, function):
    result = validate(db, f"SELECT 'a' COLLATE {collation}", {"blocked_functions": [function]})
    assert result["allowed"], result
    assert not validate(db, f"SELECT {function}('a')", {"blocked_functions": [function]})["allowed"]
    for sql in (f"SELECT 'a' COLLATE {collation} = 'A'",
                f"SELECT s FROM (VALUES ('a'),('b')) v(s) ORDER BY s COLLATE {collation}"):
        assert validate(db, sql)["allowed"], validate(db, sql)
        result = validate(db, sql, {"blocked_functions": [function]})
        assert result["code"] == "forbidden", result
        assert any(v["rule"] == "function" and v["function_name"] == function
                   for v in result["violations"]), result


def test_host_created_type_can_shadow_builtin(db):
    db.execute("CREATE SCHEMA custom; CREATE TYPE custom.integer AS VARCHAR; SET search_path='custom'")
    result = validate(db, 'SELECT \'a\'::custom."integer"')
    assert result["allowed"], result


def test_json_type_needs_no_permission(db):
    result = validate(db, "SELECT '{}'::JSON")
    assert result["allowed"], result


def test_pivot_and_window_blocks(expressions):
    for sql in ["SELECT sum(x) OVER () FROM t", "PIVOT t ON x IN (1) USING sum(x)"]:
        result = validate(expressions, sql, {"blocked_functions": ["sum"]})
        assert result["code"] == "forbidden" and result["error_message"] == "", result


def test_named_pivot_enum_uses_host_type(db):
    db.execute("CREATE TYPE pivot_values AS ENUM ('a'); CREATE TABLE p(k VARCHAR, x INTEGER)")
    result = validate(db, "PIVOT p ON k IN pivot_values USING sum(x)")
    assert result["allowed"], result
    db.execute("PIVOT p ON k IN pivot_values USING sum(x)").fetchall()


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
    # Catalog, session, and configuration inspection is opt-in; the clock and RNG are defaults.
    for sql, name in [("current_schema", "current_schema"), ("current_catalog", "current_catalog"),
                      ("current_setting('threads')", "current_setting"), ("getvariable('x')", "getvariable")]:
        result = validate(db, "SELECT " + sql)
        assert result["code"] == "forbidden", (name, result)
        configure(db, {"allowed_functions": [name]})
        assert validate(db, "SELECT " + sql, {"allowed_functions": [name]})["allowed"]
        configure(db)


def test_host_can_disable_type_autoload(db):
    db.execute("SET autoload_known_extensions=false; SET autoinstall_known_extensions=false")
    before = db.execute("SELECT loaded FROM duckdb_extensions() WHERE extension_name='inet'").fetchone()
    assert before == (False,)
    result = validate(db, "SELECT '127.0.0.1'::INET")
    assert result["code"] == "binding"
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


def test_single_arrow_lambda_overlap_and_keyword_workaround(expressions):
    expressions.execute("SET lambda_syntax='ENABLE_SINGLE_ARROW'; CREATE VIEW v_json AS SELECT json_extract(j, 'a') z FROM t")
    options = {"use_default_functions": False, "allowed_functions": ["list_transform", "+"]}
    sql = "SELECT list_transform(arr, x -> x + 1), z FROM t, v_json"
    assert not validate(expressions, sql, options)["allowed"]
    assert validate(expressions, sql.replace("x ->", "lambda x:"), options)["allowed"]


@pytest.mark.parametrize("name", ["row_number", "rank", "dense_rank"])
def test_nonaggregate_windows_in_trusted_view(db, name):
    # Non-aggregate windows have no catalog entry; the plan walk names them so they are reported and, where the
    # caller wrote them, blockable. Inside the view they are the view's.
    db.execute(f"CREATE VIEW w AS SELECT {name}() OVER () n")
    result = validate(db, "SELECT * FROM w")
    assert result["allowed"] and any(f["name"] == name and f["type"] == "window" for f in result["functions"])
    assert validate(db, "SELECT * FROM w", {"blocked_functions": [name]})["allowed"]
    result = validate(db, f"SELECT {name}() OVER () FROM w", {"blocked_functions": [name]})
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == name


def test_types_are_independent_of_table_policy(db):
    db.execute("CREATE SCHEMA private; CREATE TYPE private.customer AS ENUM ('a')")
    options = {"allowed_tables": []}
    configure(db, options)
    assert validate(db, "SELECT 'a'::private.customer")["allowed"]
    assert validate(db, "SELECT '{}'::JSON")["allowed"]
    # Builtins are namespace-independent; adding a cast does not require system catalog access.
    assert validate(db, "SELECT 1::INTEGER", {"allowed_tables": []})["allowed"]


@pytest.mark.parametrize("defaults", [True, False])
def test_defaults_combine_with_explicit_function_permissions(db, defaults):
    db.execute("CREATE MACRO custom(x) AS x")
    options = {"use_default_functions": defaults, "allowed_functions": ["custom"]}
    configure(db, options)
    assert validate(db, "SELECT custom(1)")["allowed"]
    assert validate(db, "SELECT abs(1)")["allowed"] is defaults
    assert validate(db, "SELECT custom(1), abs(1)", options)["allowed"] is defaults
    assert validate(db, "SELECT 1", {"use_default_functions": False, "allowed_functions": []})["allowed"]
    assert not validate(db, "SELECT custom(1)", {"use_default_functions": False, "allowed_functions": []})["allowed"]
    assert not validate(db, "SELECT custom(1)", {"blocked_functions": ["custom"]})["allowed"]
    configure(db, {**options, "blocked_functions": ["custom"]})
    assert not validate(db, "SELECT custom(1)", {"blocked_functions": []})["allowed"]
