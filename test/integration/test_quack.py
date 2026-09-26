"""Real transport, supported local binding, and demonstrated unsupported remote bind routes."""
import os

import duckdb
import pytest

from support.artifact import ENGINE_MAJOR, EXTENSION, connect, literal
from support.audit import decisions, enable
from support.enforcement import DENIED, enforce
from support.quack import quack_fixture
from support.quack_capi import CConnection
from support.typed_helpers import configure, function_rules, grants, rule, validate

pytestmark = pytest.mark.skipif(os.getenv("GATEKEEPER_QUACK_TESTS") != "1", reason="opt-in Quack fixture")
POLICY = {"allowed_tables": [rule("remote", ("main",), "orders"), rule("memory", ("main",), "local_orders")]}
REMOTE_GRANTS = grants("quack_query", "quack_query_by_name", catalog="system", schema_path=("main",), type="table")


@pytest.fixture
def remote():
    with quack_fixture() as fixture:
        yield fixture


def local_binding(db):
    if ENGINE_MAJOR >= 2:
        db.execute("SET disabled_optimizers='remote_pushdown'")


def test_real_transport_and_binding_executes_opaque_queries(remote):
    assert remote.client.execute("SELECT sum(amount) FROM remote.main.orders").fetchone() == (50,)
    assert remote.requests
    remote.clear()
    remote.client.execute("EXPLAIN SELECT * FROM quack_query_by_name('remote', 'SELECT * FROM ticking')").fetchall()
    assert remote.executions == [1, 2]


@pytest.mark.parametrize("function", ["quack_query", "quack_query_by_name"])
def test_caller_delegation_never_bind_even_when_granted(remote, function):
    db = remote.client
    target = literal(remote.uri) if function == "quack_query" else "'remote'"
    token = ", token=" + literal(remote.token) if function == "quack_query" else ""
    sql = f"SELECT * FROM {function}({target}, ?{token})"
    fixed = sql.replace("?", "'SELECT * FROM ticking'")
    policy = {"allowed_tables": [rule()], "allowed_functions": REMOTE_GRANTS}
    configure(db, policy)
    # Never-bind is independent of qualified blocks: even explicit grants and no blocks
    # cannot admit caller-authored delegation.
    for query in (fixed, sql):
        result = validate(db, query, {**policy, "blocked_functions": []})
        assert not result["allowed"] and result["code"] == "forbidden", result
    assert remote.requests == [] and remote.executions == []
    with db.cursor() as agent:
        local_binding(agent)
        enforce(agent)
        for query, args in [(fixed, []), (sql, ["SELECT * FROM ticking"])]:
            remote.clear()
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute(query, args).fetchall()
            assert remote.requests == [] and remote.executions == []


def test_attached_scope_validation_enforcement_parameters_and_log_only(remote):
    db = remote.client
    blocks = function_rules("md5", catalog="system", schema_path=("main",), type="scalar")
    local_sql = "SELECT md5('caller') FROM local_orders"
    assert validate(db, local_sql, {**POLICY, "blocked_functions": function_rules(
        "md5", catalog="remote", schema_path=("main",), type="scalar")})["allowed"]
    assert not validate(db, local_sql, {**POLICY, "blocked_functions": blocks})["allowed"]
    configure(db, {**POLICY, "allowed_functions": blocks, "blocked_functions": blocks})
    # A request cannot clear the global block, and a matching grant cannot override it.
    assert not validate(db, local_sql, {**POLICY, "blocked_functions": []})["allowed"]
    result = validate(db, "SELECT sum(amount) FROM remote.main.orders", POLICY)
    assert result["allowed"] == (ENGINE_MAJOR >= 2), result
    assert remote.requests == []
    if result["allowed"]:
        assert result["caller_objects"] == [{"catalog": "remote", "schema_path": ["main"], "table": "orders", "type": "table"}]
    enable(db, "debug")
    with db.cursor() as agent:
        local_binding(agent)
        enforce(agent)
        remote.clear()
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(local_sql)
        assert remote.requests == []
        for sql, args in [("SELECT sum(amount) FROM remote.main.orders", []),
                          ("SELECT amount FROM remote.main.orders WHERE id=?", [2])]:
            remote.clear()
            if ENGINE_MAJOR >= 2:
                assert agent.execute(sql, args).fetchone() == ((30,) if args else (50,))
                assert remote.requests
            else:
                with pytest.raises(duckdb.PermissionException, match=DENIED):
                    agent.execute(sql, args)
                assert remote.requests == []
        for sql in ["SELECT * FROM remote.main.secret", "INSERT INTO remote.main.orders VALUES (3,40)"]:
            remote.clear()
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute(sql)
            assert remote.requests == []
        db.execute("SET gatekeeper_log_only=true")
        assert agent.execute("SELECT * FROM remote.main.secret").fetchone() == (999,)
        found = decisions(db, "mode='log_only'")
        assert len(found) == 1 and not found[0]["allowed"]


@pytest.mark.parametrize("body", ["SELECT * FROM remote.main.ticking",
                                  "SELECT * FROM quack_query_by_name('remote', 'SELECT * FROM ticking')",
                                  "SELECT * FROM remote.query('SELECT * FROM ticking')"])
def test_opaque_trusted_definition_private_bind_refusal_and_deferred_residual(remote, body):
    db = remote.client
    db.execute("CREATE VIEW trusted AS " + body)
    policy = {"allowed_tables": [rule()], "allowed_functions": REMOTE_GRANTS}
    configure(db, policy)
    remote.clear()
    result = validate(db, "SELECT * FROM trusted", policy)
    assert not result["allowed"]
    if "quack_query_by_name" in body:
        violation, = result["violations"]
        assert (violation["catalog"], violation["schema_path"], violation["function_name"],
                violation["function_type"]) == ("system", ["main"], "quack_query_by_name", "table")
    assert remote.requests == [] and remote.executions == []
    with db.cursor() as agent:
        local_binding(agent)
        enforce(agent)
        with pytest.raises(duckdb.PermissionException, match="Gatekeeper denied|unsupported remote authorization scope"):
            agent.execute("SELECT * FROM trusted")
        assert remote.requests == [] and remote.executions == []
        # Unsupported: parameters defer private authorization until after the engine's bind.
        # A denial is NOT proof of zero I/O. The trusted body already executed on the server.
        with pytest.raises(duckdb.PermissionException, match="Gatekeeper denied|unsupported remote authorization scope"):
            agent.execute("SELECT * FROM trusted WHERE id=?", [1]).fetchall()
        assert remote.requests and remote.executions, (body, remote.requests, remote.executions)


def test_local_view_over_base_table_and_identity_collision(remote):
    db = remote.client
    db.execute("CREATE VIEW trusted AS SELECT *, md5('host') AS fingerprint FROM remote.main.orders; CREATE TABLE orders(id INTEGER)")
    policy = {"allowed_tables": [rule("memory", ("main",), "trusted"), rule("memory", ("main",), "orders")],
              "blocked_functions": function_rules("md5", catalog="system", schema_path=("main",), type="scalar")}
    configure(db, policy)
    assert validate(db, "SELECT * FROM memory.main.orders", policy)["allowed"]
    result = validate(db, "SELECT * FROM trusted", policy)
    assert result["allowed"] == (ENGINE_MAJOR >= 2)
    if result["allowed"]:
        assert result["caller_objects"] == [{"catalog": "memory", "schema_path": ["main"], "table": "trusted", "type": "view"}]
        assert {"catalog": "remote", "schema_path": ["main"], "table": "orders", "type": "table"} in result["objects"]
    assert not validate(db, "SELECT * FROM remote.main.orders", policy)["allowed"]
    assert not validate(db, "SELECT * FROM trusted, remote.main.orders", policy)["allowed"]
    assert not validate(db, "SELECT md5('caller') FROM trusted", policy)["allowed"]
    assert remote.requests == []


def test_schema_qualification_contract(remote):
    remote.server.execute("CREATE SCHEMA other; CREATE TABLE other.orders(id INTEGER, amount INTEGER); INSERT INTO other.orders VALUES (10,999)")
    remote.attach(remote.client, "refreshed")
    assert remote.client.execute("SELECT sum(amount) FROM refreshed.other.orders").fetchone() == ((50,) if ENGINE_MAJOR < 2 else (999,))
    remote.clear()
    assert validate(remote.client, "SELECT * FROM refreshed.other.orders", {"allowed_tables": [rule("refreshed", ("other",), "orders")]})["allowed"] == (ENGINE_MAJOR >= 2)
    assert remote.requests == []


def test_server_sessions_require_independent_installation(remote):
    db, server = remote.client, remote.server
    configure(server, {"allowed_tables": []})
    with server.cursor() as unrelated:
        enforce(unrelated)
        assert db.execute("SELECT * FROM remote.main.secret").fetchone() == (999,)
    db.execute("SELECT * FROM quack_query_by_name('remote', 'CALL gatekeeper_enforce()')").fetchall()
    with pytest.raises(duckdb.Error, match="Gatekeeper denied"):
        db.execute("SELECT * FROM remote.main.secret").fetchall()
    remote.attach(db, "second")
    assert db.execute("SELECT * FROM second.main.secret").fetchone() == (999,)


@pytest.mark.parametrize("parameterized", [False, True])
def test_held_prepared_base_table_reauthorized(remote, parameterized):
    db = CConnection()
    try:
        db.query("LOAD " + literal(EXTENSION))
        for name in ("httpfs", "quack"):
            db.query("LOAD " + literal(os.environ["GATEKEEPER_" + name.upper() + "_EXTENSION"]))
        db.query(f"ATTACH {literal(remote.uri)} AS remote (TYPE quack, TOKEN {literal(remote.token)})")
        if ENGINE_MAJOR >= 2:
            db.query("SET disabled_optimizers='remote_pushdown'")
        sql = "SELECT * FROM remote.main.orders" + (" WHERE id=?" if parameterized else "")
        with db.prepare(sql) as (handle, error):
            assert error is None
            assert db.execute(handle, 1 if parameterized else None) is None
            db.query("CALL gatekeeper_configure(allowed_tables := [], allowed_functions := "
                     "[{catalog:'system',schema_path:['main'],name:'quack_query_by_name',type:'table'}])")
            db.query("CALL gatekeeper_enforce()")
            remote.clear()
            assert "Gatekeeper denied" in db.execute(handle, 1 if parameterized else None)
            assert remote.requests == []
        remote.clear()
        with db.prepare("SELECT * FROM quack_query_by_name('remote', ?)") as (handle, error):
            if error:
                assert "Gatekeeper denied" in error
            else:
                assert "Gatekeeper denied" in db.execute(handle, "SELECT * FROM ticking")
        assert remote.requests == [] and remote.executions == []
        # 1.5 native Prepare() itself has no QueryBegin text gate. Constant arguments can
        # already execute during preparation; only execution is guaranteed to be refused.
        remote.clear()
        with db.prepare("SELECT * FROM quack_query_by_name('remote', 'SELECT * FROM ticking')") as (handle, error):
            if ENGINE_MAJOR >= 2:
                assert error and "Gatekeeper denied" in error
                assert remote.requests == [] and remote.executions == []
            else:
                assert remote.requests and remote.executions
                if not error:
                    assert "Gatekeeper denied" in db.execute(handle)
    finally:
        db.close()


@pytest.mark.parametrize("before", [False, True])
def test_unrelated_host_extensions_load_before_or_after_enforcement(before):
    with duckdb.connect(config={"allow_unsigned_extensions": True}) as host:
        if before:
            host.execute("LOAD " + literal(os.environ["GATEKEEPER_HTTPFS_EXTENSION"]))
        host.execute("LOAD " + literal(EXTENSION))
        with host.cursor() as agent:
            enforce(agent)
            if not before:
                host.execute("LOAD " + literal(os.environ["GATEKEEPER_HTTPFS_EXTENSION"]))
            assert host.execute("SELECT loaded FROM duckdb_extensions() WHERE extension_name='httpfs'").fetchone() == (True,)
            assert agent.execute("SELECT 42").fetchone() == (42,)


def test_caller_delegation_log_only_records_but_executes(remote):
    db = remote.client
    configure(db, {"allowed_functions": REMOTE_GRANTS})
    enable(db, "debug")
    db.execute("SET gatekeeper_log_only=true")
    with db.cursor() as agent:
        local_binding(agent)
        enforce(agent)
        remote.clear()
        agent.execute("SELECT * FROM quack_query_by_name('remote', ?)", ["SELECT * FROM ticking"]).fetchall()
        assert remote.executions == [1, 2]
        found = decisions(db, "mode='log_only'")
        assert len(found) == 1 and not found[0]["allowed"], found


@pytest.mark.skipif(ENGINE_MAJOR < 2, reason="1.5 has no remote_pushdown or CONNECT")
def test_candidate_full_partial_pushdown_and_connect(remote):
    db = remote.client
    db.execute("SET disabled_optimizers=''")
    assert db.execute("SELECT sum(amount) FROM remote.main.orders").fetchone() == (50,)
    remote.clear()
    mixed = "SELECT * FROM (SELECT * FROM remote.main.orders LIMIT 1) UNION ALL SELECT * FROM local_orders"
    assert len(db.execute(mixed).fetchall()) == 2
    assert any("LIMIT 1" in sql.upper() for _, sql in remote.requests)
    db.execute("CONNECT remote")
    assert db.execute("SELECT sum(amount) FROM orders").fetchone() == (50,)
    db.execute("DISCONNECT")
    configure(db, POLICY)
    for sql in ["SELECT * FROM remote.main.orders", mixed]:
        remote.clear()
        assert not validate(db, sql, POLICY)["allowed"]
        assert remote.requests == []
    with db.cursor() as agent:
        enforce(agent)
        for sql, args in [(mixed, []), ("SELECT * FROM remote.main.orders WHERE id=?", [1]), ("CONNECT remote", [])]:
            remote.clear()
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute(sql, args)
            assert remote.requests == []
        db.execute("SET gatekeeper_log_only=true")
        for sql in ("CONNECT remote", "DISCONNECT"):
            remote.clear()
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute(sql)
            assert remote.requests == []
