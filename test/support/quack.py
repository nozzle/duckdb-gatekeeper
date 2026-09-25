"""Separate disposable DuckDB databases over loopback, with server-side execution observations.

Run through scripts/test_quack.py. Explicit paths also support a matched candidate Python engine,
Gatekeeper, Quack and httpfs build. No INSTALL/autoload or persistent credentials are used.
"""
from contextlib import contextmanager
import os
import socket
import time
import urllib.request
import uuid

from support.artifact import connect, ENGINE_MAJOR, literal


def load_quack(db):
    for name in ("httpfs", "quack"):
        db.execute("LOAD " + literal(os.environ["GATEKEEPER_" + name.upper() + "_EXTENSION"]))


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
        client.execute("CREATE TABLE local_orders(id INTEGER, amount INTEGER); INSERT INTO local_orders VALUES (3,40)")
        token = uuid.uuid4().hex
        # The release pin has no ephemeral-port support. Reserve a candidate, close, then let bind fail
        # loudly on a collision rather than accidentally contacting an unrelated listener.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        uri = f"quack:127.0.0.1:{port}"
        server.execute(f"CALL quack_serve({literal(uri)}, token={literal(token)})").fetchall()
        try:
            for attempt in range(50):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(.02)
            else:
                raise RuntimeError("Quack listener did not become ready")
            fixture = QuackFixture(server, client, uri, token)
            fixture.attach(client)
            if ENGINE_MAJOR >= 2:
                client.execute("SET disabled_optimizers='remote_pushdown'")
            fixture.clear()
            yield fixture
        finally:
            client.close()  # release sessions before stopping the listener
            server.execute("CALL quack_stop(" + literal(uri) + ")").fetchall()
