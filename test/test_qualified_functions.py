"""Namespace grants are resolved permissions, not permission to use a written leaf."""
import json

import duckdb
import pytest

from support.typed_helpers import configure, grants, policy, validate
from support.enforcement import enforce, DENIED


def test_default_shadow_and_host_macro_trust(db):
    db.execute("CREATE SCHEMA host; CREATE MACRO host.abs(x) AS md5(x::VARCHAR)")
    denied = validate(db, "SELECT host.abs(1)")
    assert denied["code"] == "forbidden"
    assert denied["violations"][0]["schema_path"] == ["host"]
    configure(db, {"allowed_functions": grants("abs", catalog="memory", schema_path=("host",), type="macro"),
                   "blocked_functions": [{"schema_path":["*"],"name":"md5"}]})
    assert validate(db, "SELECT host.abs(1)")["allowed"]
    assert not validate(db, "SELECT host.abs(1), md5('x')")["allowed"]


@pytest.mark.parametrize("kind,scalar,table", [(None, True, True), ("scalar", True, False), ("table", False, True)])
def test_same_leaf_separate_catalog_sets(db, kind, scalar, table):
    configure(db, {"use_default_functions": False,
                   "allowed_functions": grants("range", catalog="system", schema_path=("main",), type=kind)})
    assert validate(db, "SELECT range(3)")["allowed"] is scalar
    assert validate(db, "SELECT * FROM range(3)")["allowed"] is table


def test_catalog_schema_and_both_layers(db):
    db.execute("ATTACH ':memory:' AS other; CREATE SCHEMA a; CREATE SCHEMA b; "
               "CREATE MACRO a.f(x) AS x; CREATE MACRO b.f(x) AS x; CREATE MACRO other.main.f(x) AS x")
    configure(db, {"allowed_functions": grants("f", catalog="memory", schema_path=("a",))})
    assert validate(db, "SELECT a.f(1)")["allowed"]
    for sql in ["SELECT b.f(1)", "SELECT other.main.f(1)"]:
        assert not validate(db, sql, {"allowed_functions": grants("f")})["allowed"]
    assert not validate(db, "SELECT a.f(1)", {"allowed_functions": grants("f", schema_path=("b",))})["allowed"]


def test_host_alias_names_are_not_equivalent(db):
    db.execute("CREATE MACRO read_parquet(x) AS x; CREATE MACRO parquet_scan(x) AS x")
    configure(db, {"allowed_functions": grants("read_parquet", catalog="memory", schema_path=("main",), type="macro")})
    assert validate(db, "SELECT memory.main.read_parquet(1)")["allowed"]
    assert not validate(db, "SELECT memory.main.parquet_scan(1)")["allowed"]


def test_canonical_roundtrip_and_json_v2(db):
    rules = grants("abs", catalog="system", schema_path=("main",), type="ScAlAr")
    configure(db, {"json": json.dumps({"version": 2, "options": {"allowed_functions": rules}})})
    assert policy(db)["allowed_functions"] == grants("abs", catalog="system", schema_path=("main",), type="scalar")
    db.execute("SET gatekeeper_policy = current_setting('gatekeeper_policy')")
    assert validate(db, "SELECT abs(-1)")["allowed"]
    configure(db, {"allowed_functions": grants("abs", catalog=None, schema_path=("main",))})
    assert policy(db)["allowed_functions"][0]["catalog"] == ""
    assert policy(db)["allowed_functions"][0]["type"] == ""


@pytest.mark.parametrize("value", [["abs"], ["abs", {"schema_path": ["main"], "name": "abs"}]])
def test_legacy_grants_are_not_accepted(db, value):
    with pytest.raises((duckdb.BinderException, duckdb.ConversionException, duckdb.InvalidInputException)):
        configure(db, {"allowed_functions": value})


def test_unknown_kind_and_missing_namespace(db):
    for entry in [{"name":"abs"}, {"schema_path":[],"name":"abs"},
                  {"schema_path":["main"],"name":"abs","type":"pragma"}]:
        with pytest.raises(duckdb.BinderException):
            configure(db, {"allowed_functions": [entry]})


@pytest.mark.parametrize("global_block", [False, True])
def test_scoped_blocks_resolve_namespace_and_layers(db, global_block):
    db.execute("CREATE SCHEMA a; CREATE SCHEMA b; CREATE MACRO a.f(x) AS x; CREATE MACRO b.f(x) AS x")
    allowed = grants("f", catalog="memory", schema_path=("*",), type="macro")
    blocked = grants("f", catalog="memory", schema_path=("a",), type="macro")
    configure(db, {"allowed_functions": allowed, "blocked_functions": blocked if global_block else []})
    request = {"blocked_functions": [] if global_block else blocked}
    assert validate(db, "SELECT b.f(1)", request)["allowed"]
    denied = validate(db, "SELECT a.f(1)", request)
    assert denied["code"] == "forbidden"
    assert denied["violations"][0]["catalog"] == "memory"
    assert denied["violations"][0]["schema_path"] == ["a"]


@pytest.mark.parametrize("kind,scalar,table", [("scalar", False, True), ("table", True, False)])
def test_scoped_block_kind_collision(db, kind, scalar, table):
    configure(db, {"blocked_functions": grants("range", catalog="system", schema_path=("main",), type=kind)})
    assert validate(db, "SELECT range(3)")["allowed"] is scalar
    assert validate(db, "SELECT * FROM range(3)")["allowed"] is table


def test_block_aliases_do_not_canonicalize_host_names(db):
    db.execute("CREATE MACRO read_parquet(x) AS x; CREATE MACRO parquet_scan(x) AS x")
    configure(db, {"allowed_functions": grants("read_parquet", "parquet_scan", catalog="memory", schema_path=("main",)),
                   "blocked_functions": grants("read_parquet", schema_path=("*",))})
    assert validate(db, "SELECT memory.main.parquet_scan(1)")["allowed"]
    assert validate(db, "SELECT memory.main.read_parquet(1)")["code"] == "forbidden"


@pytest.mark.parametrize("name,sql,kind", [
    ("lower", "SELECT 'a' COLLATE nocase = 'A'", "scalar"),
    ("sum", "SELECT list_aggregate([1,2], 'sum')", "aggregate"),
    ("sum", "SELECT list_sum([1,2])", "aggregate"),
])
def test_collation_and_dispatch_blocks_keep_namespace_and_kind(db, name, sql, kind):
    for catalog, blocked_kind, denied in [("memory", kind, False), ("system", "table", False), ("system", kind, True)]:
        configure(db, {"allowed_functions": grants("list_aggregate", catalog="system", schema_path=("main",), type="scalar"),
                       "blocked_functions": grants(name, catalog=catalog, schema_path=("main",), type=blocked_kind)})
        assert validate(db, sql)["allowed"] is not denied


def test_prepared_validation_rechecks_qualified_block(db):
    db.execute("CREATE SCHEMA a; CREATE SCHEMA b; CREATE MACRO a.f(x) AS x; CREATE MACRO b.f(x) AS x")
    allowed = grants("f", catalog="memory", schema_path=("*",), type="macro")
    configure(db, {"allowed_functions": allowed})
    with db.cursor() as agent:
        agent.execute("PREPARE a_handle AS SELECT allowed FROM gatekeeper_validate('SELECT a.f(1)')")
        agent.execute("PREPARE b_handle AS SELECT allowed FROM gatekeeper_validate('SELECT b.f(2)')")
        configure(db, {"allowed_functions": allowed,
                       "blocked_functions": grants("f", catalog="memory", schema_path=("a",), type="macro")})
        assert agent.execute("EXECUTE b_handle").fetchone() == (True,)
        assert agent.execute("EXECUTE a_handle").fetchone() == (False,)


@pytest.mark.parametrize("entry", ["abs", {"name":"abs"}, {"schema_path":[],"name":"abs"},
                                   {"schema_path":["main"],"name":"abs","type":"any"}])
def test_invalid_block_shapes_fail_closed(db, entry):
    with pytest.raises(duckdb.Error):
        configure(db, {"blocked_functions": [entry]})
    result = validate(db, "SELECT 1", {"json": json.dumps({"version":2,"options":{"blocked_functions":[entry]}})})
    assert result["code"] == "invalid_input"


def test_implicit_shadow_is_refused_even_if_granted(db):
    db.execute("CREATE MACRO main.list_value(x) AS x")
    configure(db, {"allowed_functions": grants("list_value", catalog="memory", schema_path=("main",))})
    assert not validate(db, "SELECT [1]")["allowed"]


def test_literal_dispatch_requires_selected_aggregate(db):
    configure(db, {"use_default_functions":False,
                   "allowed_functions":grants("list_aggregate", "list_value", catalog="system", schema_path=("main",))})
    assert not validate(db, "SELECT list_aggregate([1,2], 'sum')")["allowed"]
    configure(db, {"allowed_functions":grants("list_aggregate", catalog="system", schema_path=("main",))})
    assert validate(db, "SELECT list_aggregate([1,2], 'sum')")["allowed"]
    assert not validate(db, "SELECT list_aggregate([1,2], 'su' || 'm')")["allowed"]


def test_enforcement_and_log_only_use_resolved_grants(db):
    db.execute("CREATE MACRO main.abs(x) AS x; CALL enable_logging('Gatekeeper')")
    with db.cursor() as agent:
        enforce(agent)
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute("SELECT main.abs(1)")
        configure(db, {"allowed_functions": grants("abs", catalog="memory", schema_path=("main",), type="macro")})
        assert agent.execute("SELECT main.abs(1)").fetchone() == (1,)
        configure(db)
        db.execute("SET gatekeeper_log_only=true")
        assert agent.execute("SELECT main.abs(2)").fetchone() == (2,)
        row = db.execute("SELECT allowed, code FROM duckdb_logs_parsed('Gatekeeper') "
                         "WHERE statement='SELECT main.abs(2)' AND mode='log_only'").fetchone()
        assert row == (False, "forbidden")


def test_all_overloads_and_literal_star(db):
    configure(db, {"use_default_functions": False,
                   "allowed_functions": grants("abs", "*", "-", catalog="system", schema_path=("main",), type="scalar")})
    for sql in ["SELECT abs(-1::INTEGER)", "SELECT abs(-1::DOUBLE)", "SELECT abs(-1::DECIMAL(9,2))", "SELECT 2*3"]:
        assert validate(db, sql)["allowed"], sql
    assert not validate(db, "SELECT lower('X')")["allowed"]


def test_dot_dispatch_cannot_shift_prechecked_target(db):
    configure(db, {"use_default_functions": False,
                   "allowed_functions": grants("list_aggregate", "list_value", "sum", catalog="system", schema_path=("main",))})
    result = validate(db, "SELECT l.list_aggregate('string_agg', 'sum') FROM (VALUES (['a'])) t(l)")
    assert result["code"] == "forbidden"
    assert result["violations"][0]["rule"] == "bind_time_expression"


@pytest.mark.parametrize("name,definition,sql", [
    ("->>", "(x,y) AS 'captured'", "SELECT '{}'::JSON ->> 'x'"),
    ("contains", "(x,y) AS true", "SELECT 1 IN [1,2]"),
    ("regexp_full_match", "(x,y) AS true", "SELECT 'a' SIMILAR TO 'a'"),
])
def test_parser_helpers_cannot_use_granted_host_shadows(db, name, definition, sql):
    db.execute(f'CREATE MACRO main."{name}"{definition}')
    configure(db, {"allowed_functions": grants(name, catalog="memory", schema_path=("main",), type="macro")})
    assert validate(db, sql)["code"] == "forbidden"


@pytest.mark.parametrize("name", ["mode", "entropy"])
def test_specialized_default_aggregate_identity(db, name):
    for sql in [f"SELECT {name}(x) FROM (VALUES (1),(1),(2)) t(x)",
                f"SELECT {name}(x) OVER () FROM (VALUES (1),(2)) t(x)",
                f"SELECT list_{name}([1,1,2])"]:
        result = validate(db, sql)
        assert result["allowed"], result
        assert any(f["catalog"] == "system" and f["name"] == name for f in result["functions"])


def test_host_dispatcher_leaf_is_not_a_dispatch_capability(db):
    db.execute("CREATE MACRO main.aggregate(x) AS x")
    configure(db, {"allowed_functions": grants("aggregate", catalog="memory", schema_path=("main",), type="macro")})
    assert validate(db, "SELECT aggregate(42)")["allowed"]
    assert validate(db, "SELECT main.aggregate(42)")["allowed"]


def test_subquery_count_intrinsic_matches_host_and_loadable_evidence(db):
    # A statically linked loadable has different function pointers from the Python host.
    # Both plans must identify the factory count_star, without dropping its policy checks.
    db.execute("CREATE TABLE t AS SELECT 1 x; CALL enable_logging('Gatekeeper'); SET logging_level='debug'")
    sql = "SELECT (SELECT count(*) FROM t)"
    expected = validate(db, sql)
    assert expected["allowed"], expected
    counts = [f for f in expected["functions"] if f["name"] == "count_star"]
    assert counts == [{"catalog":"system", "schema_path":["main"], "name":"count_star", "type":"aggregate"}]
    with db.cursor() as agent:
        enforce(agent)
        assert agent.execute(sql).fetchone() == (1,)
        actual = db.execute("SELECT functions FROM duckdb_logs_parsed('Gatekeeper') "
                            "WHERE mode='enforce' AND statement=?", [sql]).fetchone()[0]
        assert actual == expected["functions"]
        configure(db, {"blocked_functions":[{"schema_path":["*"],"name":"count_star"}]})
        assert validate(db, sql)["code"] == "forbidden"
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql)


@pytest.mark.parametrize("ceiling", [False, True])
def test_default_macro_dependencies_need_qualified_grants_in_strict_layers(db, ceiling):
    sql = "SELECT list_count([1,2])"
    base = grants("list_count", "list_value", catalog="system", schema_path=("main",))
    complete = base + grants("list_aggr", catalog="system", schema_path=("main",), type="scalar") + grants(
        "count", catalog="system", schema_path=("main",), type="aggregate")
    # Both dependencies are real permissions: neither wrong namespace nor wrong kind grants them.
    for rules in [base,
                  base + grants("count", catalog="system", schema_path=("main",), type="aggregate"),
                  base + grants("list_aggr", catalog="system", schema_path=("main",), type="scalar"),
                  base + grants("list_aggr", "count", catalog="memory", schema_path=("main",)),
                  base + grants("list_aggr", "count", catalog="system", schema_path=("main",), type="table")]:
        strict = {"use_default_functions":False, "allowed_functions":rules}
        configure(db, strict if ceiling else {"use_default_functions":False, "allowed_functions":complete})
        result = validate(db, sql, {"use_default_functions":True} if ceiling else strict)
        assert result["code"] == "forbidden", result
    configure(db, {"use_default_functions":False, "allowed_functions":complete})
    assert validate(db, sql)["allowed"]
    with db.cursor() as agent:
        enforce(agent)
        assert agent.execute(sql).fetchone() == (2,)
        configure(db, {"use_default_functions":False, "allowed_functions":base})
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql)
    # Host macros remain opaque capabilities even when their body expands a builtin macro.
    db.execute("CREATE MACRO main.host_count() AS list_count([1,2])")
    configure(db, {"use_default_functions":False,
                   "allowed_functions":grants("host_count", catalog="memory", schema_path=("main",), type="macro")})
    assert validate(db, "SELECT host_count()")["allowed"]


@pytest.mark.parametrize("collation,name", [("nocase","lower"), ("noaccent","strip_accents"),
                                            ("nfc","nfc_normalize"), ("de","icu_collate_de")])
def test_collation_system_capability_and_scalar_shadow(db, collation, name):
    from support.artifact import ENGINE_MAJOR
    if collation == "de" and ENGINE_MAJOR >= 2:
        name = "collate_de"
    sql = f"SELECT s FROM (VALUES ('a'), ('B')) t(s) ORDER BY s COLLATE {collation}"
    db.execute(f'CREATE MACRO main."{name}"(s) AS s')
    strict = {"use_default_functions":False,
              "allowed_functions":grants(name, catalog="system", schema_path=("main",), type="scalar")}
    configure(db, strict)
    result = validate(db, sql)
    assert result["allowed"], result
    assert {"catalog":"system","schema_path":["main"],"name":name,"type":"scalar"} in result["functions"]
    assert validate(db, f'SELECT main."{name}"(\'a\')')["code"] == "forbidden"
    assert validate(db, sql, {"blocked_functions":[{"schema_path":["*"],"name":name}]})["code"] == "forbidden"
    assert validate(db, sql, {"allowed_functions":grants(name, catalog="memory", schema_path=("main",))})["code"] == "forbidden"
    assert validate(db, sql, {"allowed_functions":grants(name, catalog="system", schema_path=("main",), type="table")})["code"] == "forbidden"
    with db.cursor() as agent:
        enforce(agent)
        assert len(agent.execute(sql).fetchall()) == 2
