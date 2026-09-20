"""Bind-time expression restrictions and complete-binding dependency evidence."""
import pytest

from support.artifact import by_parser
from support.typed_helpers import configure, validate


@pytest.mark.parametrize("sql", [
    "SELECT 1 LIMIT len(repeat('x', 200000000))",
    "SELECT 1 OFFSET abs(2)",
    "SELECT * FROM range(abs(3))", "SELECT * FROM range(1+2)",
    "SELECT COLUMNS(concat('x', '')) FROM t",
    "SELECT COLUMNS(lambda c: len(repeat(c, 200000000))>0) FROM t",
    "PIVOT t ON x IN (1+2) USING sum(x)",
    "SELECT quantile_cont(x, abs(0.5)) FROM t",
    "SELECT quantile_cont(x, [0.2, abs(0.8)]) FROM t",
    "SELECT percentile_cont(abs(0.5)) WITHIN GROUP (ORDER BY x) FROM t",
    "SELECT quantile_cont(x, abs(0.5)) OVER () FROM t",
    "SELECT unnest([1,2], max_depth:=abs(2))",
    "SELECT * FROM t AT (VERSION => abs(2))",
])
def test_bind_time_computation_rejected_before_binding(db, sql):
    # t deliberately does not exist; preflight must win over the binding error.
    result = validate(db, sql)
    assert result["code"] == "forbidden" and result["error_message"] == "", result
    assert "bind_time_expression" in {v["rule"] for v in result["violations"]}, result
    assert result["objects"] == result["functions"] == []


@pytest.mark.parametrize("sql", [
    "SELECT x FROM t LIMIT 2 OFFSET 0", "SELECT x FROM t LIMIT 50 PERCENT",
    "SELECT quantile_cont(x, [0.2, 0.8]) FROM t",
    "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY x) FROM t",
    "SELECT * FROM t TABLESAMPLE reservoir(10 ROWS)",
    "SELECT COLUMNS('x') FROM t", "SELECT COLUMNS(['x']) FROM t",
    "SELECT unnest([1,2], max_depth:=2)", "SELECT unnest([[1]], recursive:=true)",
    "PIVOT t ON x IN (1, 2) USING sum(x)",
    "SELECT * FROM range(3)", "SELECT repeat('x', 3) FROM t",
])
def test_literal_bind_time_forms_remain_usable(db, sql):
    db.execute("CREATE TABLE t(x INTEGER)")
    result = validate(db, sql)
    assert result["allowed"], result


@pytest.mark.parametrize("sql", [
    "SELECT x FROM t WHERE x=?", "SELECT x FROM t WHERE x=$1", "SELECT x FROM t WHERE x=$value",
    "SELECT * FROM t LIMIT ?", "SELECT * FROM t LIMIT $n OFFSET $offset", "SELECT $1::INTEGER",
    "SELECT x FROM t WHERE x=$1::INT AND x=$1::INT", "SELECT x FROM t WHERE x=$1 LIMIT $2",
])
def test_parameters_with_complete_binding(db, sql):
    db.execute("CREATE TABLE t(x INTEGER)")
    result = validate(db, sql)
    assert result["allowed"], result


def test_conflicting_parameter_types_require_rebinding(db):
    db.execute("CREATE TABLE t(x INTEGER)")
    # INTEGER comparison and BIGINT LIMIT invalidate the shared parameter type in DuckDB.
    result = validate(db, "SELECT x FROM t WHERE x=$1 LIMIT $1")
    assert result["code"] == "binding" and not result["allowed"], result


@pytest.mark.parametrize("sql", ["SELECT $1", "SELECT abs($1)", "SELECT * FROM range($1)"])
def test_parameter_dependent_binding_fails_closed(db, sql):
    result = validate(db, sql)
    assert result["code"] == "binding" and "parameter" in result["error_message"].lower(), result
    assert result["objects"] == result["functions"] == []


def test_parameter_does_not_override_function_policy(db):
    result = validate(db, "SELECT * FROM read_csv(?)")
    assert result["code"] == "forbidden"
    assert any(v["function_name"] == "read_csv" for v in result["violations"])
    configure(db, {"allowed_functions": ["read_csv"]})
    result = validate(db, "SELECT * FROM read_csv(?)", {"allowed_functions": ["read_csv"]})
    assert result["code"] == "binding"


def test_objects_and_functions_are_resolved_deduplicated_sorted(db):
    db.execute("CREATE SCHEMA Reporting; CREATE TABLE Reporting.Orders(x INTEGER); "
               "CREATE VIEW Reporting.V AS SELECT abs(x) x FROM Reporting.Orders; "
               "CREATE MACRO report() AS TABLE SELECT * FROM Reporting.Orders")
    result = validate(db, "WITH cte AS (SELECT * FROM Reporting.V) SELECT abs(a.x), abs(b.x) FROM cte a, Reporting.V b")
    assert result["allowed"], result
    assert result["objects"] == [
        {"catalog": "memory", "schema": "Reporting", "table": "Orders", "type": "table"},
        {"catalog": "memory", "schema": "Reporting", "table": "V", "type": "view"},
    ]
    assert {"catalog": "system", "schema": "main", "name": "abs", "type": "scalar"} in result["functions"]
    for field, leaf in [("objects", "table"), ("functions", "name")]:
        tuples = [(v["catalog"], v["schema"], v[leaf], v["type"]) for v in result[field]]
        assert tuples == sorted(set(tuples))
    configure(db, {"allowed_functions": ["report"]})
    macro = validate(db, "SELECT * FROM report()", {"allowed_functions": ["report"]})
    assert macro["allowed"] and macro["objects"] == result["objects"][:1]
    assert {"catalog": "memory", "schema": "main", "name": "report", "type": "table_macro"} in macro["functions"]


@pytest.mark.parametrize("sql,options", [
    ("SELECT abs(x), missing FROM t", {}),
    ("SELECT * FROM t", {"allowed_tables": []}),
    ("SELECT abs(x) FROM t; SELECT * FROM missing", {}),
    ("SELECT * FROM", {}), (None, {}), ("SELECT 1", {"blocked_functions": [None]}),
])
def test_failed_results_never_expose_partial_dependencies(db, sql, options):
    db.execute("CREATE TABLE t(x INTEGER)")
    result = validate(db, sql, options)
    assert not result["allowed"]
    assert result["objects"] == result["functions"] == []


def test_temp_shadowing_and_explicit_catalog(db):
    db.execute("CREATE TABLE t(x INTEGER); CREATE TEMP TABLE t(x INTEGER)")
    result = validate(db, "SELECT * FROM t", {"allowed_tables": [{"schema": "main", "table": "t"}]})
    assert result["allowed"] and result["objects"][0]["catalog"] == "temp"
    assert not validate(db, "SELECT * FROM t", {
        "allowed_tables": [{"catalog": "memory", "schema": "main", "table": "t"}]})["allowed"]


def test_qualified_function_capability_diagnostics(db):
    result = validate(db, "SELECT * FROM SYSTEM.main.query('SELECT 1')")
    violation = next(v for v in result["violations"] if v["rule"] == "dynamic_sql")
    assert violation["catalog"] == "SYSTEM" and violation["schema"] == "main"
    # The position is the parser's: the default parser stamps the qualified table function's location, the
    # PEG parser stamps none, and the violation reports NULL rather than inventing one.
    assert violation["position"] == by_parser(postgres=14, peg=None)


def test_quoted_dependency_identities_are_not_dotted_strings(db):
    db.execute('CREATE SCHEMA "a.b"; CREATE TABLE "a.b"."x.y"(x INT)')
    result = validate(db, 'SELECT * FROM "a.b"."x.y"')
    assert result["allowed"]
    assert result["objects"] == [{"catalog": "memory", "schema": "a.b", "table": "x.y", "type": "table"}]


def test_table_macro_cte_shadowing_differs_from_view(db):
    configure(db, {"allowed_functions": ["m"]})
    db.execute("CREATE TABLE t AS SELECT 1 x; CREATE MACRO m() AS TABLE SELECT * FROM t; CREATE VIEW v AS SELECT * FROM t")
    macro = validate(db, "WITH t AS (SELECT 2 x) SELECT * FROM m()", {"allowed_functions": ["m"]})
    view = validate(db, "WITH t AS (SELECT 2 x) SELECT * FROM v")
    assert macro["allowed"] and view["allowed"]
    assert macro["objects"] == []
    assert {o["table"] for o in view["objects"]} == {"t", "v"}


def test_literal_constructor_shadow_cannot_evaluate_macro(db):
    db.execute("CREATE MACRO main.list_value(x) AS repeat('x', 200000000)")
    result = validate(db, "SELECT * FROM range(list_value(1))")
    assert result["code"] == "forbidden" and result["error_message"] == "", result
    assert any(v["rule"] == "bind_time_expression" for v in result["violations"])


def test_non_catalog_window_is_reported_without_invented_namespace(db):
    result = validate(db, "SELECT row_number() OVER ()")
    assert result["allowed"]
    assert {"catalog": "", "schema": "", "name": "row_number", "type": "window"} in result["functions"]


def test_typed_parameter_execution_uses_same_text(db):
    db.execute("CREATE TABLE t AS SELECT 42 x")
    sql = "SELECT x FROM t WHERE x=$value LIMIT $n"
    result = validate(db, sql)
    assert result["allowed"]
    assert db.execute(sql, {"value": 42, "n": 1}).fetchall() == [(42,)]


def test_host_enum_allows_label_introspection(db):
    db.execute("CREATE TYPE status AS ENUM ('pending','done')")
    sql = "SELECT enum_range(NULL::status)"
    result = validate(db, sql)
    assert result["allowed"]
    assert db.execute(sql).fetchone() == (["pending", "done"],)


def test_bind_time_named_reader_options_are_checked(db):
    for suffix in ["header=contains(repeat('x',200000000),'x')", "header:=contains(repeat('x',200000000),'x')"]:
        result = validate(db, "SELECT * FROM read_csv('missing.csv', " + suffix + ")", {"allowed_functions": ["read_csv"]})
        assert result["code"] == "forbidden" and result["error_message"] == ""
        assert any(v["rule"] == "bind_time_expression" for v in result["violations"])


def test_local_connection_profile_after_setup(db):
    db.execute("CREATE SCHEMA reporting; CREATE TABLE reporting.t(x INT); "
               "SET enable_external_access=false; SET autoload_known_extensions=false; "
               "SET autoinstall_known_extensions=false; SET memory_limit='512MB'; SET threads=1; "
               "SET search_path='memory.reporting'; SET lock_configuration=true")
    result = validate(db, "SELECT x FROM t WHERE x=?")
    assert result["allowed"] and result["objects"][0]["schema"] == "reporting"


def test_qualified_builtin_containers_and_named_fields(db):
    db.execute("CREATE TABLE t(x INT)")
    for sql in ["SELECT quantile_cont(x, system.main.list_value(0.2,0.8)) FROM t",
                "SELECT * FROM unnest([struct_pack(x:=1)])",
                "SELECT * FROM unnest([system.main.struct_pack(x:=1)])",
                "SELECT unnest([[1]], recursive:=true)"]:
        db.execute(sql).fetchall()
        result = validate(db, sql)
        assert result["allowed"], result


def test_equals_is_not_a_named_struct_or_scalar_unnest_argument(db):
    import duckdb
    for sql in ["SELECT struct_pack(x=1)", "SELECT unnest([1,2], recursive=true)"]:
        with pytest.raises(duckdb.BinderException):
            db.execute(sql)
    result = validate(db, "SELECT unnest([1,2], recursive=true)")
    assert result["code"] == "forbidden"


@pytest.mark.parametrize("sql", [
    "SELECT * FROM d, unnest(d.arr)", "SELECT * FROM d CROSS JOIN unnest(d.arr) AS u(v)",
    "SELECT * FROM d, range(d.x)", "SELECT * FROM d, generate_series(1,d.x)",
    "SELECT * FROM d, unnest(list_transform(arr, lambda v: v+1))",
])
def test_correlated_table_in_out_arguments(db, sql):
    db.execute("CREATE TABLE d AS SELECT 2 x, [1,2] arr")
    db.execute(sql).fetchall()
    result = validate(db, sql)
    assert result["allowed"], result


def test_in_out_exception_requires_builtin_identity(db):
    db.execute("CREATE TABLE d(x INT); CREATE MACRO main.range(x) AS TABLE SELECT x")
    result = validate(db, "SELECT * FROM d, range(d.x)")
    assert result["code"] == "forbidden" and result["error_message"] == "", result
    assert any(v["rule"] == "bind_time_expression" for v in result["violations"])


def test_unresolved_column_does_not_relax_standard_reader(db):
    result = validate(db, "SELECT * FROM read_csv(repeat(not_a_column,200000000))", {"allowed_functions": ["read_csv"]})
    assert result["code"] == "forbidden" and result["error_message"] == ""
    assert any(v["rule"] == "bind_time_expression" for v in result["violations"])


@pytest.mark.parametrize("sql", [
    "SELECT * FROM generate_series(DATE '2024-01-01',DATE '2024-01-03',INTERVAL '1 day')",
    "SELECT * FROM range(TIMESTAMP '2024-01-01',TIMESTAMP '2024-02-01',INTERVAL '1 month')",
    "SELECT * FROM unnest(['a','b']::VARCHAR[])", "SELECT 1 LIMIT 5::INT",
])
def test_typed_bind_time_literals(db, sql):
    db.execute(sql).fetchall()
    result = validate(db, sql)
    assert result["allowed"], result


def test_typed_reader_parameter_still_requires_value(db):
    result = validate(db, "SELECT * FROM range(?::BIGINT)")
    assert result["code"] == "binding" and "parameter" in result["error_message"].lower()


def test_cast_does_not_admit_computation(db):
    result = validate(db, "SELECT 1 LIMIT len(repeat('x',200000000))::INT")
    assert result["code"] == "forbidden" and result["error_message"] == ""


@pytest.mark.parametrize("sql", [
    "SELECT * FROM unnest(repeat('x',200000000), recursive:=true)",
    "SELECT * FROM unnest(repeat('x',200000000), recursive=true)",
])
def test_runtime_argument_exception_does_not_admit_other_computation(db, sql):
    result = validate(db, sql)
    assert result["code"] == "forbidden" and result["error_message"] == "", result
    assert any(v["rule"] == "bind_time_expression" for v in result["violations"])


@pytest.mark.parametrize("sql", [
    "SELECT range(3) FROM d, range(d.x)",
    "SELECT generate_series(1,3) FROM d, generate_series(1,d.x)",
    "SELECT * FROM d, range(d.x,len(repeat('x',3)))",
    "SELECT 1 LIMIT TRY_CAST('5' AS INT)",
])
def test_runtime_call_and_scalar_names_coexist(db, sql):
    db.execute("CREATE TABLE d AS SELECT 1 x")
    db.execute(sql).fetchall()
    result = validate(db, sql)
    assert result["allowed"], result
