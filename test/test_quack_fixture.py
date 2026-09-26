"""Fixture lifecycle regressions using only local sockets and simulated SQL results."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
from threading import Thread
from unittest.mock import MagicMock

import duckdb
import pytest

from support import quack


@pytest.fixture
def competitor():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"unrelated listener")

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            yield server.server_port, requests
        finally:
            server.shutdown()
            thread.join()


def test_collision_exhaustion_never_probes_or_attaches(monkeypatch, competitor):
    port, requests = competitor
    server, client = MagicMock(), MagicMock()
    for db in (server, client):
        db.__enter__.return_value = db
    monkeypatch.setattr(quack, "connect", MagicMock(side_effect=[server, client]))
    monkeypatch.setattr(quack, "load_quack", lambda db: None)
    monkeypatch.setattr(quack, "ENGINE_MAJOR", 1)
    monkeypatch.setattr(quack, "candidate_port", lambda: port)
    starts = []

    def execute(sql):
        if sql.startswith("CALL quack_serve"):
            starts.append(sql)
            # Reproduce the pinned constructor's synchronous bind and error propagation.
            with socket.socket() as listener:
                try:
                    listener.bind(("127.0.0.1", port))
                except OSError as error:
                    raise duckdb.IOException("Failed to bind DuckDB Quack RPC server") from error
            pytest.fail("competing listener did not own the port")
        return server

    server.execute.side_effect = execute
    with pytest.raises(duckdb.IOException, match="Failed to bind"):
        with quack.quack_fixture():
            pytest.fail("fixture yielded after failed startup")
    assert len(starts) == 5
    assert requests == []
    assert not any(call.args[0].startswith("ATTACH") for call in client.execute.call_args_list)
    assert server.__exit__.called and client.__exit__.called


def test_collision_retry_uses_successful_endpoint(monkeypatch):
    monkeypatch.setattr(quack, "ENGINE_MAJOR", 1)
    monkeypatch.setattr(quack, "candidate_port", MagicMock(side_effect=[12345, 23456]))
    server = MagicMock()
    server.execute.side_effect = [duckdb.IOException("Failed to bind DuckDB Quack RPC server"), server]
    server.fetchall.return_value = [("quack:127.0.0.1:23456", "http://127.0.0.1:23456", "fixture-token")]
    assert quack.start_listener(server, "fixture-token") == "quack:127.0.0.1:23456"
    assert "23456" in server.execute.call_args.args[0]


def test_unrelated_startup_error_is_not_retried(monkeypatch):
    monkeypatch.setattr(quack, "ENGINE_MAJOR", 2)
    server = MagicMock()
    server.execute.side_effect = duckdb.IOException("startup failed")
    with pytest.raises(duckdb.IOException, match="startup failed"):
        quack.start_listener(server, "fixture-token")
    assert server.execute.call_count == 1


def test_ephemeral_port_uses_returned_endpoint(monkeypatch):
    monkeypatch.setattr(quack, "ENGINE_MAJOR", 2)
    server = MagicMock()
    server.execute.return_value.fetchall.return_value = [
        ("quack://127.0.0.1:23456", "http://127.0.0.1:23456", "fixture-token")]
    assert quack.start_listener(server, "fixture-token") == "quack://127.0.0.1:23456"
    assert "quack:127.0.0.1:0" in server.execute.call_args.args[0]


@pytest.mark.parametrize("rows", [
    [(False,)],
    [("quack:127.0.0.1:0", "http://127.0.0.1:0", "fixture-token")],
    [("quack:127.0.0.1:23456", "http://127.0.0.1:34567", "fixture-token")],
    [("quack:127.0.0.1:23456", "http://127.0.0.1:23456", "wrong-token")],
])
def test_invalid_startup_result_is_rejected(monkeypatch, rows):
    monkeypatch.setattr(quack, "ENGINE_MAJOR", 2)
    server = MagicMock()
    server.execute.return_value.fetchall.return_value = rows
    with pytest.raises(RuntimeError, match="Unexpected quack_serve"):
        quack.start_listener(server, "fixture-token")


def test_wrong_server_marker_fails_and_stops_listener(monkeypatch):
    server, client = MagicMock(), MagicMock()
    for db in (server, client):
        db.__enter__.return_value = db
    monkeypatch.setattr(quack, "connect", MagicMock(side_effect=[server, client]))
    monkeypatch.setattr(quack, "load_quack", lambda db: None)
    monkeypatch.setattr(quack, "start_listener", lambda db, token: "quack:127.0.0.1:23456")
    client.execute.return_value.fetchall.return_value = [("another fixture",)]
    with pytest.raises(RuntimeError, match="identity mismatch"):
        with quack.quack_fixture():
            pytest.fail("fixture yielded with the wrong server identity")
    assert client.close.called
    assert server.execute.call_args.args[0] == "CALL quack_stop('quack:127.0.0.1:23456')"
