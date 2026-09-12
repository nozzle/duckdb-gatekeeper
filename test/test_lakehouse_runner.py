import subprocess
import importlib.util

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
