"""Configuration lifecycle and non-bypassable policy layers."""
import concurrent.futures

import duckdb
import pytest

from support.artifact import connect
from support.typed_helpers import configure, policy, validate


def test_inspection_reset_and_complete_replacement(db):
    defaults = policy(db)
    assert defaults["restrict_tables"] is False
    assert defaults["allowed_tables"] == []
    assert defaults["blocked_tables"] == []
    assert all(value is not None for value in defaults.values())
    configure(db, {"allowed_tables": [], "blocked_functions": ["MD5", "md5"]})
    assert policy(db)["restrict_tables"] is True
    assert policy(db)["blocked_functions"] == ["md5"]
    configure(db, {"use_default_functions": False})
    assert policy(db) == {**defaults, "use_default_functions": False}
    db.execute("RESET GLOBAL gatekeeper_policy")
    assert policy(db) == defaults
    configure(db, {"blocked_functions": ["lower"]})
    db.execute("RESET gatekeeper_policy")
    assert policy(db) == defaults


def test_canonical_policy_shape_is_pinned(db):
    """The canonical setting has exactly the supported policy fields."""
    expected = {"use_default_functions",
                "allowed_functions", "blocked_functions",
                "allowed_tables", "blocked_tables", "restrict_tables"}
    assert set(policy(db)) == expected
    for statement in ("CALL gatekeeper_configure(unknown := [])",
                      "SELECT * FROM gatekeeper_validate('SELECT 1', unknown := [])"):
        with pytest.raises(duckdb.Error, match="unknown"):
            db.execute(statement)
    before = policy(db)
    # DuckDB discards extra STRUCT keys, while CALL rejects unknown options.
    db.execute("SET gatekeeper_policy = struct_insert(current_setting('gatekeeper_policy'), unknown := true)")
    assert policy(db) == before
    with pytest.raises(duckdb.Error):
        db.execute("CALL gatekeeper_configure(unknown := true)")
    assert policy(db) == before


@pytest.mark.parametrize("value", [1, 2, 0, -1, 1.5, True, None, "1"])
def test_statement_limit_is_not_configurable(db, value):
    configure(db, {"blocked_functions": ["md5"]})
    before = policy(db)
    for operation in [lambda: configure(db, {"max_statements": value}),
                      lambda: validate(db, "SELECT 1", {"max_statements": value})]:
        with pytest.raises(duckdb.Error, match="max_statements"):
            operation()
        assert policy(db) == before
    # Extra canonical STRUCT keys are discarded by DuckDB and cannot change the cap.
    db.execute("SET gatekeeper_policy = struct_insert(current_setting('gatekeeper_policy'), max_statements := ?)", [value])
    assert policy(db) == before
    result = validate(db, "SELECT 1; SELECT 2")
    assert result["code"] == "forbidden" and result["violations"][0]["rule"] == "limit"


def test_configuration_is_nontransactional_and_requires_table_function(db):
    db.execute("BEGIN")
    configure(db, {"blocked_functions": ["md5"]})
    db.execute("ROLLBACK")
    assert policy(db)["blocked_functions"] == ["md5"]
    with pytest.raises(duckdb.Error, match="table function"):
        db.execute("SELECT gatekeeper_configure()")


@pytest.mark.parametrize("options", [
    {"unknown": ["main"]}, {"use_default_functions": "false"}, {"use_default_functions": 1},
    {"allowed_functions": [1]}, {"allowed_functions": [None]},
    {"allowed_tables": [{"schema": "main", "table": "t", "catlog": "memory"}]},
    {"allowed_tables": [{"schema": "main", "tabel": "t"}]},
])
def test_strict_parameterized_call_preserves_policy_on_failure(db, options):
    configure(db, {"blocked_functions": ["md5"]})
    before = policy(db)
    with pytest.raises(duckdb.Error):
        configure(db, options)
    assert policy(db) == before


def test_any_catalog_is_canonically_empty_and_quoted_parameters(db):
    db.execute("CREATE TABLE t(x INT); ATTACH ':memory:' AS lake; CREATE TABLE lake.main.t(x INT)")
    configure(db, {"allowed_tables": [{"catalog": None, "schema": "a'b", "table": "t"},
                                      {"schema": "main", "table": "t"}]})
    # The canonical setting never contains NULL; '' spells "any catalog".
    assert policy(db)["allowed_tables"] == [{"catalog": "", "schema": "a'b", "table": "t"},
                                            {"catalog": "", "schema": "main", "table": "t"}]
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


def test_set_requires_consistent_table_restriction(db):
    db.execute("CREATE TABLE t(x INT); CREATE TABLE secret(x INT)")
    before = policy(db)
    entry = "[{catalog:'memory', schema:'main', 'table':'t'}]"
    with pytest.raises(duckdb.Error, match="nonempty allowed_tables requires restrict_tables"):
        db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), allowed_tables := " + entry + ")")
    assert policy(db) == before
    db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), "
               "restrict_tables := true, allowed_tables := " + entry + ")")
    assert validate(db, "SELECT * FROM t")["allowed"]
    assert not validate(db, "SELECT * FROM secret")["allowed"]
    before = policy(db)
    with pytest.raises(duckdb.Error, match="nonempty allowed_tables requires restrict_tables"):
        db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), restrict_tables := false)")
    assert policy(db) == before
    db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), allowed_tables := [])")
    assert not validate(db, "SELECT * FROM t")["allowed"]
    db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), restrict_tables := false)")
    assert validate(db, "SELECT * FROM secret")["allowed"]


@pytest.mark.parametrize("argument", ['allowed_tables := []::STRUCT(schema VARCHAR, "table" VARCHAR, extra VARCHAR)[]',
                                     "use_default_functions := NULL::BOOLEAN",
                                     "blocked_functions := [], blocked_functions := ['md5']",
                                     "blocked_functions = [], blocked_functions = ['md5']"])
def test_call_rejects_unknown_empty_identity_fields_and_duplicates(db, argument):
    # A bad option is a bind error for CALL gatekeeper_configure as it is for gatekeeper_validate (README:
    # "DuckDB error at bind" for both); the duplicate spelling is the same in both.
    with pytest.raises(duckdb.BinderException) as caught:
        db.execute("CALL gatekeeper_configure(" + argument + ")")
    if "blocked_functions := [], " in argument or "blocked_functions = [], " in argument:
        assert "duplicate Gatekeeper option" in str(caught.value), caught.value
        with pytest.raises(duckdb.BinderException, match="duplicate Gatekeeper option"):
            db.execute("SELECT * FROM gatekeeper_validate('SELECT 1', blocked_functions := [], blocked_functions := ['md5'])")


@pytest.mark.parametrize("empty", ["[]", "[]::INTEGER[]", "[]::VARCHAR[]"])
def test_call_empty_lists_deny_all_identities(db, empty):
    db.execute("CREATE TABLE t(x INT); CREATE TYPE customer AS ENUM ('a')")
    db.execute(f"CALL gatekeeper_configure(allowed_tables := {empty})")
    assert policy(db)["restrict_tables"]
    assert policy(db)["allowed_tables"] == []
    assert not validate(db, "SELECT * FROM t")["allowed"]
    assert validate(db, "SELECT NULL::customer")["allowed"]


def test_prepare_and_explain_do_not_mutate_and_execution_rechecks_lock(db):
    before = policy(db)
    # SQL PREPARE's grammar excludes CALL; the equivalent table SELECT is preparable.
    db.execute("PREPARE cfg AS SELECT * FROM gatekeeper_configure(blocked_functions := $1)")
    db.execute("PREPARE literal_cfg AS SELECT * FROM gatekeeper_configure(blocked_functions := ['abs'])")
    db.execute("EXPLAIN CALL gatekeeper_configure(blocked_functions := ['lower'])").fetchall()
    db.execute("CREATE VIEW cfg_view AS SELECT * FROM gatekeeper_configure(blocked_functions := ['upper'])")
    assert policy(db) == before
    # A configure spelled as a SELECT (EXECUTE of one, here) takes effect when its row is produced; DuckDB 2.0
    # produces a SELECT's rows only when they are read, so read them. CALL runs at once on both engines.
    db.execute("EXECUTE cfg(['md5'])").fetchall()
    assert policy(db)["blocked_functions"] == ["md5"]
    db.execute("EXECUTE cfg(['lower'])").fetchall()
    assert policy(db)["blocked_functions"] == ["lower"]
    db.execute("SET lock_configuration = true")
    for sql in ["EXECUTE cfg([])", "EXECUTE literal_cfg", "SELECT * FROM cfg_view"]:
        with pytest.raises(duckdb.Error, match="locked"):
            db.execute(sql).fetchall()


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
    configure(db, {"blocked_functions": ["md5"]})
    db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), blocked_functions := ['lower'])")
    assert policy(db)["blocked_functions"] == ["lower"]
    db.execute("RESET gatekeeper_policy")
    assert policy(db)["blocked_functions"] == []


@pytest.mark.parametrize("statement", [
    "SET SESSION gatekeeper_policy = current_setting('gatekeeper_policy')",
    "RESET SESSION gatekeeper_policy",
])
def test_session_configuration_rejected(db, statement):
    with pytest.raises(duckdb.Error, match="global-only"):
        db.execute(statement)


def test_set_validation_and_cast_limitations(db):
    before = policy(db)
    for expr in ["NULL", "{'use_default_functions': false, 'unknown': ['main']}",
                 "struct_update(current_setting('gatekeeper_policy'), blocked_functions := [NULL])",
                 "struct_update(current_setting('gatekeeper_policy'), allowed_tables := [{schema:'main', tabel:'t'}])"]:
        with pytest.raises(duckdb.Error):
            db.execute("SET gatekeeper_policy = " + expr)
        assert policy(db) == before
    # A complete STRUCT plus an extra key is silently cast by DuckDB before our callback.
    db.execute("SET gatekeeper_policy = struct_insert(current_setting('gatekeeper_policy'), unknown := ['main'])")
    assert policy(db) == before
    db.execute("SET gatekeeper_policy = struct_update(current_setting('gatekeeper_policy'), blocked_functions := ['MD5', 'md5'])")
    assert policy(db)["blocked_functions"] == ["md5"]


def test_prepare_validation_reads_global_at_execution(db):
    db.execute("PREPARE v AS SELECT allowed FROM gatekeeper_validate('SELECT md5(''x'')', blocked_functions := [])")
    assert db.execute("EXECUTE v").fetchone()[0]
    with db.cursor() as other:
        configure(other, {"blocked_functions": ["md5"]})
    assert not db.execute("EXECUTE v").fetchone()[0]
    db.execute("RESET gatekeeper_policy")
    assert db.execute("EXECUTE v").fetchone()[0]


@pytest.mark.parametrize("global_options,overrides,sql,rule", [
    ({"blocked_functions": ["md5"]}, {"blocked_functions": []}, "SELECT md5('x')", "function"),
    ({"use_default_functions": False}, {"use_default_functions": True}, "SELECT abs(1)", "function"),
    ({"use_default_functions": False}, {"allowed_functions": ["abs"]}, "SELECT abs(1)", "function"),
    ({"blocked_functions": ["range"]}, {"blocked_functions": []}, "SELECT * FROM range(3)", "function"),
    ({}, {"allowed_functions": ["read_csv_auto"]}, "SELECT * FROM 'missing.csv'", "function"),
    ({}, {"allowed_functions": ["json_serialize_plan"]}, "SELECT json_serialize_plan('SELECT 1')", "dynamic_sql"),
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


def test_table_ceiling_does_not_restrict_types(db):
    db.execute("CREATE SCHEMA private; CREATE TYPE private.customer AS ENUM ('a'); CREATE TABLE private.t(x INT)")
    configure(db, {"allowed_tables": []})
    assert validate(db, "SELECT NULL::private.customer")["allowed"]
    assert not validate(db, "SELECT * FROM private.t", {"allowed_tables": [{"catalog": "*", "schema": "*", "table": "*"}]})["allowed"]


def test_resolved_denies_in_trusted_expansions_obey_both_layers(db):
    # A global block reaches what the caller writes, whether the request repeats it or not; a host macro's or
    # view's own use of the blocked function is the definition's and is not reached in either layer.
    db.execute("CREATE MACRO m(x) AS abs(x); CREATE VIEW v AS SELECT abs(1) x")
    configure(db, {"allowed_functions": ["m"], "blocked_functions": ["abs"]})
    for sql in ["SELECT m(1)", "SELECT * FROM v"]:
        result = validate(db, sql, {"blocked_functions": []})
        assert result["allowed"], (sql, result)
        assert any(f["name"] == "abs" for f in result["functions"]), (sql, result)
    for sql in ["SELECT abs(1)", "SELECT m(1), abs(2)", "SELECT abs(x) FROM v"]:
        result = validate(db, sql, {"blocked_functions": []})
        assert result["code"] == "forbidden" and result["objects"] == result["functions"] == [], (sql, result)
        assert result["violations"][0]["function_name"] == "abs", (sql, result)


@pytest.mark.parametrize("sql", [
    "CALL gatekeeper_configure()", "SELECT * FROM gatekeeper_configure()",
    "SELECT * FROM system.main.gatekeeper_configure()", "SELECT * FROM cfg_view", "SELECT * FROM cfg_macro()",
])
def test_configuration_is_never_admitted_as_submitted_sql(db, sql):
    db.execute("CREATE VIEW cfg_view AS SELECT * FROM gatekeeper_configure(); "
               "CREATE MACRO cfg_macro() AS TABLE SELECT * FROM gatekeeper_configure()")
    options = {"allowed_functions": ["gatekeeper_configure", "cfg_macro"], "blocked_functions": ["md5"]}
    configure(db, options)
    before = policy(db)
    result = validate(db, sql, options)
    assert result["code"] in {"forbidden", "unsupported"} and not result["allowed"], result
    assert result["objects"] == result["functions"] == []
    assert policy(db) == before


def test_atomic_replacements_across_connections(db):
    policies = [{"blocked_functions": ["md5"], "use_default_functions": False},
                {"blocked_functions": ["lower"], "use_default_functions": True}]
    configure(db, policies[0])

    def worker(i):
        with db.cursor() as conn:
            for _ in range(30):
                configure(conn, policies[i % 2])
                snapshot = policy(conn)
                assert (snapshot["blocked_functions"], snapshot["use_default_functions"]) in [(["md5"], False), (["lower"], True)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(worker, range(4)))
    with connect() as independent:
        assert policy(independent)["blocked_functions"] == []
