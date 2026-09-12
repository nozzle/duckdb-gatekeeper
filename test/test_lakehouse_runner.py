import subprocess
import importlib.util
from types import SimpleNamespace

import pytest

from test_gatekeeper import ROOT

spec = importlib.util.spec_from_file_location("lakehouse_runner", ROOT / "scripts/test_lakehouses.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_cleanup_preserves_original_failure(monkeypatch, capsys):
    original = RuntimeError("startup failed")

    def run(command, **kwargs):
        if "up" in command:
            raise original
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(runner.subprocess, "run", run)
    with pytest.raises(RuntimeError) as caught:
        runner.main()
    assert caught.value is original
    assert "cleanup also failed" in capsys.readouterr().err


def test_cleanup_failure_fails_successful_run(monkeypatch):
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def run(command, **kwargs):
        if "down" in command:
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(runner.subprocess, "run", run)
    monkeypatch.setattr(runner.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    with pytest.raises(subprocess.CalledProcessError):
        runner.main()


def test_fixture_closes_connection_on_setup_failure(monkeypatch, tmp_path):
    fixture_spec = importlib.util.spec_from_file_location("lakehouse_fixture", ROOT / "test/integration/test_lakehouses.py")
    fixture = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture)

    class Connection:
        closed = False

        def execute(self, sql):
            raise RuntimeError("LOAD failed")

        def close(self):
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(fixture.duckdb, "connect", lambda **kwargs: connection)
    generator = fixture.lake.__wrapped__(SimpleNamespace(param="ducklake"), tmp_path)
    with pytest.raises(RuntimeError, match="LOAD failed"):
        next(generator)
    assert connection.closed
