"""Real Quack transport and local authorization scope. See docs/quack.md for the support matrix."""
import os
from concurrent.futures import ThreadPoolExecutor

import duckdb
import pytest

from support.artifact import ENGINE_MAJOR, EXTENSION, connect, literal
from support.audit import decisions, enable
from support.enforcement import DENIED, enforce
from support.quack import quack_fixture
from support.quack_capi import CConnection
from support.typed_helpers import configure, grants, rule, validate

pytestmark = pytest.mark.skipif(os.getenv("GATEKEEPER_QUACK_TESTS") != "1", reason="opt-in Quack fixture")
POLICY = {"allowed_tables": [rule("remote", ("main",), "orders"), rule("memory", ("main",), "local_orders")]}


@pytest.fixture
def remote():
    with quack_fixture() as fixture:
        yield fixture


def test_real_transport_and_binding_executes_opaque_queries(remote):
    db = remote.client
    assert db.execute("SELECT sum(amount) FROM remote.main.orders").fetchone() == (50,)
    assert any("orders" in sql for _, sql in remote.requests)
    remote.clear()
    # EXPLAIN never executes the local scan, but its bind executes the delegated query on the server.
    db.execute("EXPLAIN SELECT * FROM quack_query_by_name('remote', 'SELECT * FROM ticking')").fetchall()
    assert remote.executions == [1, 2]
    assert any("ticking" in sql for _, sql in remote.requests)


def test_attached_read_scope_validation_enforcement_parameters_and_log_only(remote):
    db = remote.client
    configure(db, POLICY)
    sql = "SELECT sum(amount) FROM remote.main.orders"
    result = validate(db, sql, POLICY)
    assert remote.requests == []  # validation never sends the scan query
    assert result["allowed"] == (ENGINE_MAJOR >= 2), result
    if ENGINE_MAJOR >= 2:
        assert result["caller_objects"] == [{"catalog": "remote", "schema_path": ["main"],
                                             "table": "orders", "type": "table"}]
    else:
        assert "unsupported remote authorization scope" in str(result)
    enable(db, "debug")
    with db.cursor() as agent:
        if ENGINE_MAJOR >= 2:
            agent.execute("SET disabled_optimizers='remote_pushdown'")
        enforce(agent)
        for query, args in [(sql, []), ("SELECT amount FROM remote.main.orders WHERE id=?", [2])]:
            remote.clear()
            if ENGINE_MAJOR >= 2:
                assert agent.execute(query, args).fetchone() == ((50,) if not args else (30,))
                assert remote.requests
            else:
                with pytest.raises(duckdb.PermissionException, match=DENIED):
                    agent.execute(query, args)
                assert remote.requests == []
        for query in ["SELECT * FROM remote.main.secret", "INSERT INTO remote.main.orders VALUES (4,50)"]:
            remote.clear()
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute(query)
            assert remote.requests == []
        db.execute("SET gatekeeper_log_only=true")
        remote.clear()
        assert agent.execute("SELECT * FROM remote.main.secret").fetchone() == (999,)
        assert remote.requests
        found = decisions(db, "mode='log_only'")
        assert len(found) == 1 and not found[0]["allowed"], found


@pytest.mark.parametrize("body", ["SELECT * FROM remote.main.ticking",
                                  "SELECT * FROM quack_query_by_name('remote', 'SELECT * FROM ticking')"])
def test_opaque_validation_refused_even_through_trusted_view(remote, body):
    db = remote.client
    # Host DDL itself can bind the remote query. Discard those setup observations explicitly.
    db.execute("CREATE VIEW trusted AS " + body)
    remote.clear()
    policy = {"allowed_tables": [rule()], "allowed_functions": grants("quack_query", "quack_query_by_name", catalog="system", schema_path=("main",), type="table")}
    configure(db, policy)
    for sql in [body, "SELECT * FROM trusted"]:
        result = validate(db, sql, policy)
        assert not result["allowed"] and "unsupported" in str(result), result
        assert remote.requests == [] and remote.executions == []
    with db.cursor() as agent:
        if ENGINE_MAJOR >= 2:
            agent.execute("SET disabled_optimizers='remote_pushdown'")
        enforce(agent)
        for sql in [body, "SELECT * FROM trusted"]:
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute(sql)
            assert remote.requests == [] and remote.executions == []


def test_local_trusted_view_and_mixed_query_evidence(remote):
    db = remote.client
    db.execute("CREATE VIEW trusted AS SELECT * FROM remote.main.orders")
    policy = {"allowed_tables": [rule("memory", ("main",), "trusted")]}
    configure(db, policy)
    remote.clear()
    result = validate(db, "SELECT * FROM trusted", policy)
    assert result["allowed"] == (ENGINE_MAJOR >= 2), result
    if result["allowed"]:
        assert result["caller_objects"] == [{"catalog": "memory", "schema_path": ["main"],
                                             "table": "trusted", "type": "view"}]
        assert {"catalog": "remote", "schema_path": ["main"], "table": "orders", "type": "table"} in result["objects"]
    assert not validate(db, "SELECT * FROM trusted, remote.main.orders", policy)["allowed"]
    assert remote.requests == []
    with db.cursor() as agent:
        if ENGINE_MAJOR >= 2:
            agent.execute("SET disabled_optimizers='remote_pushdown'")
        enforce(agent)
        if ENGINE_MAJOR >= 2:
            assert agent.execute("SELECT sum(amount) FROM trusted").fetchone() == (50,)
        else:
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute("SELECT * FROM trusted")
        remote.clear()
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute("SELECT * FROM trusted, remote.main.orders")
        assert remote.requests == []


def test_unrelated_local_identity_does_not_authorize_remote_object(remote):
    db = remote.client
    db.execute("CREATE TABLE orders(id INTEGER)")
    policy = {"allowed_tables": [rule("memory", ("main",), "orders")]}
    configure(db, policy)
    assert validate(db, "SELECT * FROM memory.main.orders", policy)["allowed"]
    remote.clear()
    assert not validate(db, "SELECT * FROM remote.main.orders", policy)["allowed"]
    assert remote.requests == []


def test_release_schema_qualification_cannot_be_an_authorization_contract(remote):
    server, db = remote.server, remote.client
    server.execute("CREATE SCHEMA other; CREATE TABLE other.orders(id INTEGER, amount INTEGER); "
                   "INSERT INTO other.orders VALUES (10,999)")
    # Reattach to snapshot the new schema. The release implementation binds the local other.orders,
    # but its scan sends FROM orders, which resolves to main.orders on the server.
    remote.attach(db, "refreshed")
    assert db.execute("SELECT sum(amount) FROM refreshed.other.orders").fetchone() == ((50,) if ENGINE_MAJOR < 2 else (999,))
    remote.clear()
    policy = {"allowed_tables": [rule("refreshed", ("other",), "orders")]}
    assert validate(db, "SELECT * FROM refreshed.other.orders", policy)["allowed"] == (ENGINE_MAJOR >= 2)
    assert remote.requests == []


def test_server_connections_are_independent_and_explicit_session_installation(remote):
    db, server = remote.client, remote.server
    configure(server, {"allowed_tables": []})
    # A global server policy and even enforcement of a different server connection do not latch RPC sessions.
    with server.cursor() as unrelated:
        enforce(unrelated)
        assert db.execute("SELECT * FROM remote.main.secret").fetchone() == (999,)
    db.execute("SELECT * FROM quack_query_by_name('remote', 'CALL gatekeeper_enforce()')").fetchall()
    with pytest.raises(duckdb.Error, match="Gatekeeper denied"):
        db.execute("SELECT * FROM remote.main.secret").fetchall()
    # Another attachment creates another logical connection and does not inherit that installation.
    remote.attach(db, "second")
    assert db.execute("SELECT * FROM second.main.secret").fetchone() == (999,)


@pytest.mark.parametrize("parameterized", [False, True])
def test_held_prepared_handle_and_prepare_only_do_not_delegate_when_enforced(remote, parameterized):
    db = CConnection()
    try:
        # Exercise both load orders; the callback also wraps Quack loaded after Gatekeeper.
        if parameterized:
            db.query("LOAD " + literal(EXTENSION))
        for name in ("httpfs", "quack"):
            db.query("LOAD " + literal(os.environ["GATEKEEPER_" + name.upper() + "_EXTENSION"]))
        if not parameterized:
            db.query("LOAD " + literal(EXTENSION))
        db.query(f"ATTACH {literal(remote.uri)} AS remote (TYPE quack, TOKEN {literal(remote.token)})")
        if ENGINE_MAJOR >= 2:
            db.query("SET disabled_optimizers='remote_pushdown'")
        sql = "SELECT * FROM remote.main.orders" + (" WHERE id=?" if parameterized else "")
        with db.prepare(sql) as (handle, error):
            assert error is None
            assert db.execute(handle, 1 if parameterized else None) is None
            db.query("CALL gatekeeper_configure(allowed_tables := [])")
            db.query("CALL gatekeeper_enforce()")
            remote.clear()
            assert "Gatekeeper denied" in db.execute(handle, 1 if parameterized else None)
            assert remote.requests == []
        # An explicit opaque table-function bind must be stopped even when Prepare() has no QueryBegin.
        remote.clear()
        with db.prepare("SELECT * FROM quack_query_by_name('remote', 'SELECT * FROM ticking')") as (_, error):
            assert error and "Gatekeeper denied" in error
        assert remote.requests == [] and remote.executions == []
        with db.prepare("SELECT * FROM quack_query_by_name('remote', ?)") as (handle, error):
            # Some engines defer this bind to execution because its VARCHAR parameter is unresolved.
            if error:
                assert "Gatekeeper denied" in error
            else:
                assert "Gatekeeper denied" in db.execute(handle, "SELECT * FROM ticking")
        assert remote.requests == [] and remote.executions == []
    finally:
        db.close()


def test_parameterized_opaque_execution_and_log_only(remote):
    db = remote.client
    configure(db, {"allowed_tables": [rule()], "allowed_functions": grants("quack_query_by_name", catalog="system", schema_path=("main",), type="table")})
    enable(db, "debug")
    with db.cursor() as agent:
        if ENGINE_MAJOR >= 2:
            agent.execute("SET disabled_optimizers='remote_pushdown'")
        enforce(agent)
        remote.clear()
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute("SELECT * FROM quack_query_by_name('remote', ?)", ["SELECT * FROM ticking"])
        assert remote.requests == [] and remote.executions == []
        db.execute("SET gatekeeper_log_only=true")
        assert agent.execute("SELECT * FROM quack_query_by_name('remote', ?)", ["SELECT * FROM ticking"]).fetchall()
        assert remote.executions == [1, 2]
        found = decisions(db, "mode='log_only'")
        assert len(found) == 1 and not found[0]["allowed"], found


@pytest.mark.skipif(ENGINE_MAJOR < 2, reason="LOAD AS is a 2.0 feature")
def test_aliased_quack_load_is_guarded(remote):
    with connect(autoinstall_known_extensions=False, autoload_known_extensions=False) as host:
        host.execute("LOAD " + literal(os.environ["GATEKEEPER_HTTPFS_EXTENSION"]))
        host.execute("LOAD " + literal(os.environ["GATEKEEPER_QUACK_EXTENSION"]) + " AS q")
        remote.attach(host)
        host.execute("SET disabled_optimizers='remote_pushdown'")
        configure(host, {"allowed_tables": [rule()], "allowed_functions": grants("quack_query_by_name", catalog="system", schema_path=("main",), type="table")})
        with host.cursor() as agent:
            enforce(agent)
            remote.clear()
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute("SELECT * FROM quack_query_by_name('remote', ?)", ["SELECT * FROM ticking"]).fetchall()
            assert remote.requests == [] and remote.executions == []


def test_enforcement_seals_future_quack_loads():
    with connect(autoinstall_known_extensions=False, autoload_known_extensions=False) as host:
        host.execute("LOAD " + literal(os.environ["GATEKEEPER_HTTPFS_EXTENSION"]))
        with host.cursor() as agent:
            enforce(agent)
            suffixes = [""] + ([" AS q"] if ENGINE_MAJOR >= 2 else [])
            for suffix in suffixes:
                with pytest.raises(duckdb.Error, match="remote setup is sealed"):
                    host.execute("LOAD " + literal(os.environ["GATEKEEPER_QUACK_EXTENSION"]) + suffix)


def test_concurrent_activation_publishes_one_guarded_catalog(remote):
    import threading
    start = threading.Barrier(3)
    host = remote.client
    with host.cursor() as first, host.cursor() as second, ThreadPoolExecutor(2) as pool:
        def activate(connection):
            start.wait(timeout=30)
            enforce(connection)
        futures = [pool.submit(activate, connection) for connection in (first, second)]
        start.wait(timeout=30)
        for future in futures:
            future.result(timeout=30)
        remote.clear()
        for agent in (first, second):
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute("SELECT * FROM quack_query_by_name('remote', ?)", ["SELECT * FROM ticking"]).fetchall()
        assert remote.requests == [] and remote.executions == []


@pytest.mark.parametrize("gatekeeper_first", [False, True])
def test_concurrent_load_barrier(remote, gatekeeper_first):
    barrier = os.environ.get("GATEKEEPER_QUACK_BARRIER")
    if not barrier:
        pytest.fail("Set GATEKEEPER_QUACK_BARRIER to the GATEKEEPER_REMOTE_PROBES artifact")
    with duckdb.connect(config={"allow_unsigned_extensions": True, "autoload_known_extensions": False,
                                "autoinstall_known_extensions": False}) as host:
        host.execute("LOAD " + literal(os.environ["GATEKEEPER_HTTPFS_EXTENSION"]))
        host.execute("LOAD " + literal(barrier))
        if gatekeeper_first:
            host.execute("LOAD " + literal(EXTENSION))
        with host.cursor() as loader, host.cursor() as agent, ThreadPoolExecutor(1) as pool:
            future = pool.submit(loader.execute, "LOAD " + literal(os.environ["GATEKEEPER_QUACK_EXTENSION"]))
            try:
                host.execute("SELECT quack_load_barrier(false)").fetchall()
                if not gatekeeper_first:
                    host.execute("LOAD " + literal(EXTENSION))
                with pytest.raises(duckdb.PermissionException, match="Quack load is unfinished"):
                    enforce(agent)
            finally:
                host.execute("SELECT quack_load_barrier(true)").fetchall()
            future.result(timeout=30)
            remote.attach(host)
            if ENGINE_MAJOR >= 2:
                host.execute("SET disabled_optimizers='remote_pushdown'")
            enforce(agent)
            remote.clear()
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute("SELECT * FROM quack_query_by_name('remote', ?)", ["SELECT * FROM ticking"]).fetchall()
            assert remote.requests == [] and remote.executions == []


@pytest.mark.skipif(ENGINE_MAJOR < 2, reason="1.5 pin has no RemotePushdownOptimizer or CONNECT")
def test_candidate_full_partial_pushdown_and_connect(remote):
    db = remote.client
    db.execute("SET disabled_optimizers=''")
    # Unenforced controls establish that these routes really work on this artifact set.
    assert db.execute("SELECT sum(amount) FROM remote.main.orders").fetchone() == (50,)
    remote.clear()
    mixed = "SELECT * FROM (SELECT * FROM remote.main.orders LIMIT 1) UNION ALL SELECT * FROM local_orders"
    assert len(db.execute(mixed).fetchall()) == 2
    assert any("LIMIT 1" in sql.upper() for _, sql in remote.requests), remote.requests
    plan = db.execute("EXPLAIN " + mixed).fetchall()
    assert "union" in str(plan).lower() and "quack" in str(plan).lower(), plan
    db.execute("CONNECT remote")
    assert db.execute("SELECT sum(amount) FROM orders").fetchone() == (50,)
    db.execute("DISCONNECT")
    configure(db, POLICY)
    for sql in ["SELECT * FROM remote.main.orders", mixed]:
        remote.clear()
        result = validate(db, sql, POLICY)
        assert not result["allowed"] and "remote SQL pushdown is unsupported" in str(result)
        assert remote.requests == []
    with db.cursor() as agent:
        enforce(agent)
        for sql, args in [(mixed, []), ("SELECT * FROM remote.main.orders WHERE id=?", [1]), ("CONNECT remote", [])]:
            remote.clear()
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute(sql, args)
            assert remote.requests == []
