"""Separate disposable DuckDB databases over loopback, with server-side execution observations.

Run through scripts/test_quack.py. Explicit paths also support a matched candidate Python engine,
Gatekeeper, Quack and httpfs build. No INSTALL/autoload or persistent credentials are used.
"""
from contextlib import contextmanager
import os
import socket
from urllib.parse import urlsplit
import uuid

import duckdb

from support.artifact import connect, ENGINE_MAJOR, literal


def load_quack(db):
    for name in ("httpfs", "quack"):
        db.execute("LOAD " + literal(os.environ["GATEKEEPER_" + name.upper() + "_EXTENSION"]))


def candidate_port():
    # Only the release pin needs this handoff; a competing bind is handled by start_listener.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def start_listener(server, token):
    # Both pinned HttpQuackServer constructors bind synchronously and throw IOException on failure.
    # No network probe or ATTACH may run unless this call has completed successfully. In particular,
    # never interpret an HTTP 200 at a failed candidate port as evidence that our server started.
    for attempt in range(5):
        port = 0 if ENGINE_MAJOR >= 2 else candidate_port()
        requested = f"quack:127.0.0.1:{port}"
        try:
            rows = server.execute(f"CALL quack_serve({literal(requested)}, token={literal(token)})").fetchall()
        except duckdb.IOException as error:
            if ENGINE_MAJOR >= 2 or "Failed to bind DuckDB Quack RPC server" not in str(error):
                raise
            if attempt == 4:
                raise
            continue
        # The candidate returns its actual OS-allocated endpoint for port 0. Fail closed if a custom
        # artifact changes the startup contract; closing the owning database cleans up on this path.
        if len(rows) != 1 or len(rows[0]) != 3:
            raise RuntimeError("Unexpected quack_serve result")
        uri, url, returned_token = rows[0]
        endpoint = urlsplit(url)
        actual_port = endpoint.port
        if (endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1"
                or not actual_port or (port and actual_port != port)
                or url != f"http://127.0.0.1:{actual_port}"
                or uri not in (f"quack:127.0.0.1:{actual_port}", f"quack://127.0.0.1:{actual_port}")
                or returned_token != token):
            raise RuntimeError("Unexpected quack_serve endpoint or token")
        return uri


class QuackFixture:
    def __init__(self, server, client, uri, token):
        self.server, self.client, self.uri, self.token = server, client, uri, token
        self.request_offset = 0
        self.execution_offset = 0

    def all_requests(self):
        return self.server.execute("SELECT quack_connection_id, query FROM duckdb_logs_parsed('Quack') "
                                   "WHERE message_type='PREPARE_REQUEST' ORDER BY timestamp, context_id").fetchall()

    def execution_count(self):
        return self.server.execute("SELECT coalesce(last_value, 0) FROM duckdb_sequences() "
                                   "WHERE sequence_name='fixture_ticks'").fetchone()[0]

    @property
    def requests(self):
        return self.all_requests()[self.request_offset:]

    @property
    def executions(self):
        return list(range(1, self.execution_count() - self.execution_offset + 1))

    def attach(self, db, alias="remote"):
        # alias is a fixture constant, never caller SQL.
        db.execute(f"ATTACH {literal(self.uri)} AS {alias} (TYPE quack, TOKEN {literal(self.token)})")

    def clear(self):
        self.request_offset = len(self.all_requests())
        self.execution_offset = self.execution_count()


@contextmanager
def quack_fixture():
    # Use genuinely separate databases: cursors of one database would share local/remote tables and policy.
    with connect(autoinstall_known_extensions=False, autoload_known_extensions=False) as server, \
            connect(autoinstall_known_extensions=False, autoload_known_extensions=False) as client:
        load_quack(server)
        load_quack(client)
        # Server logs prove transmission; sequence increments survive rollback and prove execution.
        server.execute("CALL enable_logging('Quack'); SET logging_level='debug'")
        server.execute("CREATE SEQUENCE fixture_ticks")
        server.execute("CREATE TABLE orders(id INTEGER, amount INTEGER); INSERT INTO orders VALUES (1,20),(2,30)")
        server.execute("CREATE TABLE secret(value INTEGER); INSERT INTO secret VALUES (999)")
        server.execute("CREATE VIEW ticking AS SELECT nextval('fixture_ticks') AS id FROM orders")
        # Store the marker only on the owning server; the remote query must read it, not echo it.
        marker = uuid.uuid4().hex
        server.execute("CREATE TABLE fixture_identity AS SELECT " + literal(marker) + " AS marker")
        client.execute("CREATE TABLE local_orders(id INTEGER, amount INTEGER); INSERT INTO local_orders VALUES (3,40)")
        token = uuid.uuid4().hex
        uri = start_listener(server, token)
        try:
            fixture = QuackFixture(server, client, uri, token)
            fixture.attach(client)
            if ENGINE_MAJOR >= 2:
                client.execute("SET disabled_optimizers='remote_pushdown'")
            if client.execute("SELECT marker FROM remote.main.fixture_identity").fetchall() != [(marker,)]:
                raise RuntimeError("Quack fixture server identity mismatch")
            fixture.clear()
            yield fixture
        finally:
            client.close()  # release sessions before stopping the listener
            server.execute("CALL quack_stop(" + literal(uri) + ")").fetchall()
