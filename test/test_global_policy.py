"""Configuration lifecycle and non-bypassable policy layers (issue #9)."""
import concurrent.futures

import duckdb
import pytest

from test_gatekeeper import connect, db
from typed_helpers import configure, validate


def policy(db):
    return db.execute("SELECT current_setting('gatekeeper_policy')").fetchone()[0]


def test_inspection_reset_and_complete_replacement(db):
    defaults = policy(db)
    assert defaults["restrict_schemas"] is False
    assert defaults["allowed_schemas"] == []
    assert all(value is not None for value in defaults.values())
    configure(db, {"allowed_schemas": [], "blocked_functions": ["MD5", "md5"], "max_statements": 2})
    assert policy(db)["restrict_schemas"] is True
    assert policy(db)["blocked_functions"] == ["md5"]
    configure(db, {"max_statements": 3})
    assert policy(db) == {**defaults, "max_statements": 3}
    db.execute("RESET GLOBAL gatekeeper_policy")
    assert policy(db) == defaults
    configure(db, {"max_statements": 2})
    db.execute("RESET gatekeeper_policy")
    assert policy(db) == defaults


def test_configuration_is_nontransactional_and_scalar_api_is_retired(db):
    db.execute("BEGIN")
    configure(db, {"blocked_functions": ["md5"]})
    db.execute("ROLLBACK")
    assert policy(db)["blocked_functions"] == ["md5"]
    with pytest.raises(duckdb.Error, match="table function"):
        db.execute("SELECT gatekeeper_configure()")


@pytest.mark.parametrize("options", [
    {"alowed_schemas": ["main"]}, {"check_functions": "false"}, {"check_functions": 1},
    {"allowed_functions": [1]}, {"allowed_functions": [None]}, {"max_statements": 1.5},
    {"max_statements": 0}, {"max_statements": None},
    {"allowed_tables": [{"schema": "main", "table": "t", "catlog": "memory"}]},
    {"allowed_tables": [{"schema": "main", "tabel": "t"}]},
    {"allowed_types": [{"schema": "main", "type": "t", "extra": "x"}]},
    {"check_functions": False, "use_default_functions": True},
])
def test_strict_parameterized_call_preserves_old_policy_on_failure(db, options):
    configure(db, {"blocked_functions": ["md5"]})
    before = policy(db)
    with pytest.raises(duckdb.Error):
        configure(db, options)
    assert policy(db) == before


def test_any_catalog_is_canonically_empty_and_quoted_parameters(db):
    db.execute("CREATE TABLE t(x INT); ATTACH ':memory:' AS lake; CREATE TABLE lake.main.t(x INT)")
    configure(db, {"allowed_tables": [{"catalog": None, "schema": "a'b", "table": "t"},
                                      {"schema": "main", "table": "t"}],
                   "allowed_types": [{"schema": "main", "type": "customer"}]})
    # The canonical setting never contains NULL; '' spells "any catalog".
    assert policy(db)["allowed_tables"] == [{"catalog": "", "schema": "a'b", "table": "t"},
                                            {"catalog": "", "schema": "main", "table": "t"}]
    assert policy(db)["allowed_types"] == [{"catalog": "", "schema": "main", "type": "customer"}]
    assert validate(db, "SELECT * FROM memory.main.t")["allowed"]
    assert validate(db, "SELECT * FROM lake.main.t")["allowed"]
    # Round trip through direct SET is a no-op and preserves any-catalog matching.
    db.execute("SET gatekeeper_policy = current_setting('gatekeeper_policy')")
    assert policy(db)["allowed_tables"][1] == {"catalog": "", "schema": "main", "table": "t"}
    assert validate(db, "SELECT * FROM lake.main.t")["allowed"]


@pytest.mark.parametrize("entry", [
    "{catlog: 'memory', schema: 'main', \"table\": 't'}",
    "{catalog: NULL, schema: 'main', \"table\": 't'}",
    "{catalog: 'memory', schema: NULL, \"table\": 't'}",
    "NULL::STRUCT(catalog VARCHAR, schema VARCHAR, \"table\" VARCHAR)",
])
def test_set_rejects_null_nested_identity_fields(db, entry):
    """A misspelled or NULL nested field on direct SET must fail closed rather than widen to any catalog."""
    db.execute("CREATE TABLE t(x INT); ATTACH ':memory:' AS lake; CREATE TABLE lake.main.t(x INT)")
    configure(db, {"allowed_tables": [{"catalog": "memory", "schema": "main", "table": "t"}]})
    before = policy(db)
    assert not validate(db, "SELECT * FROM lake.main.t")["allowed"]
    with pytest.raises(duckdb.Error, match="NULL policy field"):
        db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), allowed_tables := ["
                   + entry + "])")
    assert policy(db) == before
    assert not validate(db, "SELECT * FROM lake.main.t")["allowed"]


def test_set_drops_extra_nested_keys_without_widening(db):
    """An extra key beside complete canonical fields is cast away silently; the identity is unchanged."""
    db.execute("CREATE TABLE t(x INT); ATTACH ':memory:' AS lake; CREATE TABLE lake.main.t(x INT)")
    configure(db, {"allowed_tables": [{"catalog": "memory", "schema": "main", "table": "t"}]})
    before = policy(db)
    db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), allowed_tables := ["
               "{catalog: 'memory', schema: 'main', \"table\": 't', catlog: 'lake'}])")
    assert policy(db) == before
    assert validate(db, "SELECT * FROM memory.main.t")["allowed"]
    assert not validate(db, "SELECT * FROM lake.main.t")["allowed"]


@pytest.mark.parametrize("argument", ['allowed_tables := []::STRUCT(schema VARCHAR, "table" VARCHAR, extra VARCHAR)[]',
                                     "max_ast_nodes := NULL::INTEGER",
                                     "blocked_functions := [], blocked_functions := ['md5']",
                                     "blocked_functions = [], blocked_functions = ['md5']"])
def test_call_rejects_unknown_empty_identity_fields_and_duplicates(db, argument):
    with pytest.raises(duckdb.Error):
        db.execute("CALL gatekeeper_configure(" + argument + ")")


def test_prepare_and_explain_do_not_mutate_and_execution_rechecks_lock(db):
    before = policy(db)
    # SQL PREPARE's grammar excludes CALL; the equivalent table SELECT is preparable.
    db.execute("PREPARE cfg AS SELECT * FROM gatekeeper_configure(blocked_functions := $1)")
    db.execute("PREPARE literal_cfg AS SELECT * FROM gatekeeper_configure(max_statements := 4)")
    db.execute("EXPLAIN CALL gatekeeper_configure(max_statements := 5)").fetchall()
    db.execute("CREATE VIEW cfg_view AS SELECT * FROM gatekeeper_configure(max_statements := 6)")
    assert policy(db) == before
    db.execute("EXECUTE cfg(['md5'])")
    assert policy(db)["blocked_functions"] == ["md5"]
    db.execute("EXECUTE cfg(['lower'])")
    assert policy(db)["blocked_functions"] == ["lower"]
    db.execute("SET lock_configuration = true")
    for sql in ["EXECUTE cfg([])", "EXECUTE literal_cfg", "SELECT * FROM cfg_view"]:
        with pytest.raises(duckdb.Error, match="locked"):
            db.execute(sql)


@pytest.mark.parametrize("statement", [
    "CALL gatekeeper_configure()", "RESET gatekeeper_policy", "RESET GLOBAL gatekeeper_policy",
    "SET gatekeeper_policy = current_setting('gatekeeper_policy')",
    "SET GLOBAL gatekeeper_policy = current_setting('gatekeeper_policy')",
])
def test_all_writers_obey_lock(db, statement):
    configure(db, {"blocked_functions": ["md5"]})
    before = policy(db)
    db.execute("SET lock_configuration = true")
    with pytest.raises(duckdb.Error, match="locked"):
        db.execute(statement)
    assert policy(db) == before
    assert not validate(db, "SELECT md5('x')", {"blocked_functions": []})["allowed"]


def test_allowed_configs_exception_is_shared_by_all_writers(db):
    db.execute("SET allowed_configs = ['gatekeeper_policy']; SET lock_configuration = true")
    configure(db, {"max_statements": 2})
    db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), max_statements := 3)")
    assert policy(db)["max_statements"] == 3
    db.execute("RESET gatekeeper_policy")
    assert policy(db)["max_statements"] == 1


@pytest.mark.parametrize("statement", [
    "SET SESSION gatekeeper_policy = current_setting('gatekeeper_policy')",
    "RESET SESSION gatekeeper_policy",
])
def test_session_configuration_rejected(db, statement):
    with pytest.raises(duckdb.Error, match="global-only"):
        db.execute(statement)


def test_set_validation_and_cast_limitations(db):
    before = policy(db)
    for expr in ["NULL", "{'max_statements': 2, 'alowed_schemas': ['main']}",
                 "struct_update(current_setting('gatekeeper_policy'), max_statements := 0)",
                 "struct_update(current_setting('gatekeeper_policy'), allowed_tables := [{schema:'main', tabel:'t'}])"]:
        with pytest.raises(duckdb.Error):
            db.execute("SET gatekeeper_policy = " + expr)
        assert policy(db) == before
    # A complete STRUCT plus an extra key is silently cast by DuckDB before our callback.
    db.execute("SET gatekeeper_policy = struct_insert(current_setting('gatekeeper_policy'), alowed_schemas := ['main'])")
    assert policy(db) == before
    db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), blocked_functions := ['MD5', 'md5'])")
    assert policy(db)["blocked_functions"] == ["md5"]


def test_prepare_validation_reads_global_at_execution(db):
    db.execute("PREPARE v AS SELECT gatekeeper_validate('SELECT md5(''x'')', blocked_functions := [])")
    assert db.execute("EXECUTE v").fetchone()[0]["allowed"]
    with db.cursor() as other:
        configure(other, {"blocked_functions": ["md5"]})
    assert not db.execute("EXECUTE v").fetchone()[0]["allowed"]
    db.execute("RESET gatekeeper_policy")
    assert db.execute("EXECUTE v").fetchone()[0]["allowed"]


@pytest.mark.parametrize("global_options,overrides,sql,rule", [
    ({"blocked_functions": ["md5"]}, {"blocked_functions": []}, "SELECT md5('x')", "function"),
    ({"use_default_functions": False}, {"check_functions": False}, "SELECT abs(1)", "function"),
    ({"max_statements": 1}, {"max_statements": 2}, "SELECT 1; SELECT 2", "limit"),
    ({"max_ast_nodes": 1}, {"max_ast_nodes": 100000}, "SELECT 1", "limit"),
    ({"max_ast_depth": 1}, {"max_ast_depth": 512}, "SELECT 1", "limit"),
    ({"max_ast_bytes": 50}, {"max_ast_bytes": 8388608}, "SELECT 1", "limit"),
    ({"allow_table_functions": False}, {"allow_table_functions": True}, "SELECT * FROM range(3)", "table_function"),
    ({"allow_recursive_ctes": False}, {"allow_recursive_ctes": True},
     "WITH RECURSIVE t AS (SELECT 1 x UNION ALL SELECT x+1 FROM t WHERE x<3) SELECT * FROM t", "recursive_cte"),
    ({"allow_file_table_references": False}, {"allow_file_table_references": True}, "SELECT * FROM 'missing.csv'", "file_table"),
    ({"allow_dynamic_sql": False}, {"allow_dynamic_sql": True, "allowed_functions": ["json_serialize_plan"]},
     "SELECT json_serialize_plan('SELECT 1')", "dynamic_sql"),
])
def test_broadening_cannot_escape_preflight(db, global_options, overrides, sql, rule):
    configure(db, global_options)
    result = validate(db, sql, overrides)
    assert result["code"] == "forbidden" and not result["error_message"], result
    assert rule in {v["rule"] for v in result["violations"]}
    assert result["objects"] == result["functions"] == []


def test_identity_layers_match_independently_and_request_can_narrow(db):
    db.execute("CREATE TABLE t(x INT); CREATE TABLE u(x INT); ATTACH ':memory:' AS lake; CREATE TABLE lake.main.t(x INT)")
    configure(db, {"allowed_tables": [{"schema": "main", "table": "t"}, {"schema": "main", "table": "u"}]})
    request = {"allowed_tables": [{"catalog": "memory", "schema": "main", "table": "t"}]}
    assert validate(db, "SELECT * FROM memory.main.t", request)["allowed"]
    assert not validate(db, "SELECT * FROM lake.main.t", request)["allowed"]
    assert not validate(db, "SELECT * FROM u", request)["allowed"]
    configure(db, request)
    broader = {"allowed_tables": [{"schema": "main", "table": "t"}, {"schema": "main", "table": "u"}]}
    assert validate(db, "SELECT * FROM memory.main.t", broader)["allowed"]
    assert not validate(db, "SELECT * FROM lake.main.t", broader)["allowed"]
    assert not validate(db, "SELECT * FROM u", broader)["allowed"]


def test_types_and_namespaces_remain_ceilings(db):
    db.execute("CREATE SCHEMA private; CREATE TYPE private.customer AS ENUM ('a'); CREATE TABLE private.t(x INT)")
    grant = {"allowed_types": [{"schema": "private", "type": "customer"}]}
    assert not validate(db, "SELECT NULL::private.customer", grant)["allowed"]
    configure(db, {**grant, "allowed_schemas": ["main"]})
    assert not validate(db, "SELECT NULL::private.customer", {"allowed_schemas": ["private"]})["allowed"]
    assert not validate(db, "SELECT * FROM private.t", {"allowed_schemas": ["private"]})["allowed"]
    configure(db, {**grant, "allowed_catalogs": []})
    assert not validate(db, "SELECT NULL::private.customer", {"allowed_catalogs": ["memory"]})["allowed"]


def test_resolved_denies_in_trusted_expansions_obey_both_layers(db):
    db.execute("CREATE MACRO m(x) AS abs(x); CREATE VIEW v AS SELECT abs(1) x")
    configure(db, {"allowed_functions": ["m"], "blocked_functions": ["abs"]})
    for sql in ["SELECT m(1)", "SELECT * FROM v"]:
        result = validate(db, sql, {"blocked_functions": []})
        assert result["code"] == "forbidden" and result["objects"] == result["functions"] == []


@pytest.mark.parametrize("sql", [
    "CALL gatekeeper_configure()", "SELECT * FROM gatekeeper_configure()",
    "SELECT * FROM system.main.gatekeeper_configure()", "SELECT * FROM cfg_view", "SELECT * FROM cfg_macro()",
])
def test_configuration_is_never_admitted_as_submitted_sql(db, sql):
    db.execute("CREATE VIEW cfg_view AS SELECT * FROM gatekeeper_configure(); "
               "CREATE MACRO cfg_macro() AS TABLE SELECT * FROM gatekeeper_configure()")
    configure(db, {"check_functions": False, "blocked_functions": ["md5"]})
    before = policy(db)
    result = validate(db, sql, {"check_functions": False, "allow_table_functions": True})
    assert result["code"] in {"forbidden", "unsupported"} and not result["allowed"], result
    assert result["objects"] == result["functions"] == []
    assert policy(db) == before


def test_atomic_replacements_across_connections(db):
    policies = [{"blocked_functions": ["md5"], "max_statements": 2},
                {"blocked_functions": ["lower"], "max_statements": 3}]
    configure(db, policies[0])

    def worker(i):
        with db.cursor() as conn:
            for _ in range(30):
                configure(conn, policies[i % 2])
                snapshot = policy(conn)
                assert (snapshot["blocked_functions"], snapshot["max_statements"]) in [(["md5"], 2), (["lower"], 3)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(worker, range(4)))
    with connect() as independent:
        assert policy(independent)["blocked_functions"] == []
