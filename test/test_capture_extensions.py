"""Collector contracts; network payloads are fixtures, native smoke uses built-ins only."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

import capture_extensions as capture


def signature(name="f", catalog="system", schema_path=None, kind="scalar", returns="INTEGER"):
    return {"name": name, "catalog": catalog, "schema_path": schema_path or ["main"],
            "kind": kind, "parameters": [], "returns": returns}


def test_delta_retains_qualified_overload_groups_and_is_reconstructible():
    old = [signature(), signature(returns="DOUBLE"), signature("gone"), signature(catalog="temp")]
    new = [signature(returns="BIGINT"), signature(catalog="temp"), signature(schema_path=["a.b", "c"]),
           signature(kind="window")]
    delta = capture.function_delta(old, new)
    assert delta["removed"] == [signature("gone")]
    assert len(delta["changed"]) == 1
    assert len(delta["changed"][0]["before"]) == 2
    remove = delta["removed"] + [r for group in delta["changed"] for r in group["before"]]
    reconstructed = [r for r in old if r not in remove] + delta["added"] + [
        r for group in delta["changed"] for r in group["after"]]
    assert sorted(reconstructed, key=capture.encoded) == sorted(new, key=capture.encoded)


def test_registry_aliases_are_engine_supplied():
    registry = [{"extension_name": "postgres_scanner", "aliases": ["postgres"]},
                {"extension_name": "sqlite_scanner", "aliases": ["sqlite", "sqlite3"]}]
    assert capture.canonical_name("postgres", registry) == "postgres_scanner"
    assert capture.canonical_name("sqlite3", registry) == "sqlite_scanner"
    assert capture.canonical_name("ui", registry) == "ui"
    with pytest.raises(ValueError):
        capture.canonical_name("x'; LOAD 'other", registry)


@pytest.mark.parametrize("message", [
    'An error occurred while autoloading extension "avro" failed',
    'Extension "/private/user/home/avro.duckdb_extension" not found.',
    'The iceberg extension requires the avro extension to be loaded!',
])
def test_dependency_hints_are_names_not_paths(message):
    assert capture.missing_dependency(message, [{"extension_name": "avro"}]) == "avro"
    assert capture.missing_dependency(message, []) is None


def test_url_rejects_unpinned_or_credentialed_sources():
    engine = {"extension_abi": "v2.0.0-alpha42986", "platform": "osx_arm64"}
    assert capture.artifact_url(engine, "core", "postgres_scanner") == (
        "https://extensions.duckdb.org/v2.0.0-alpha42986/osx_arm64/postgres_scanner.duckdb_extension.gz")
    with pytest.raises(KeyError):
        capture.artifact_url(engine, "https://user:token@example.com", "httpfs")
    with pytest.raises(ValueError):
        capture.artifact_url({**engine, "extension_abi": "../latest"}, "core", "httpfs")
    with pytest.raises(ValueError):
        capture.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.com/payload")


def test_download_hashes_compressed_and_installed_binary_before_use(tmp_path, monkeypatch):
    payload = b"fixture extension binary"
    compressed = gzip.compress(payload)

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "https://extensions.duckdb.org/v1.5.5/osx_arm64/httpfs.duckdb_extension.gz"
            return io.BytesIO(compressed)

    monkeypatch.setattr(capture.urllib.request, "build_opener", lambda *args: Opener())
    engine = {"extension_abi": "v1.5.5", "platform": "osx_arm64"}
    binary, pin = capture.download(engine, "core", "httpfs", tmp_path)
    assert binary.read_bytes() == payload
    assert pin["sha256"] == hashlib.sha256(payload).hexdigest()
    assert pin["download_sha256"] == hashlib.sha256(compressed).hexdigest()
    assert capture.download(engine, "core", "httpfs", tmp_path, pin)[1] == pin
    for field in ("sha256", "download_sha256", "url"):
        with pytest.raises(ValueError):
            capture.download(engine, "core", "httpfs", tmp_path, {**pin, field: "changed"})


def test_downloads_have_bounded_decompression(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "MAX_ARTIFACT_BYTES", 8)
    with pytest.raises(ValueError, match="size limit"):
        capture.copy_bounded(io.BytesIO(b"x" * 9), tmp_path / "artifact")


def test_parent_import_requires_no_duckdb():
    import subprocess

    code = ("import sys; sys.path.insert(0, 'scripts'); import capture_extensions; "
            "assert 'duckdb' not in sys.modules; assert 'audit_inventory' not in sys.modules")
    subprocess.run([sys.executable, "-S", "-c", code], cwd=capture.ROOT, check=True)


def test_process_isolation_removes_tokens_and_user_paths(tmp_path, monkeypatch):
    fake = tmp_path / "fake.py"
    fake.write_text("import json, os, pathlib, sys\n"
                    "pathlib.Path(sys.argv[3]).write_text(json.dumps({"
                    "'status':'ok', 'env':dict(os.environ), 'cwd':os.getcwd(), 'path':sys.path}))\n")
    monkeypatch.setattr(capture, "__file__", str(fake))
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
    monkeypatch.setenv("motherduck_token", "must-not-leak")
    monkeypatch.setenv("PYTHONPATH", "/private/personal/path")
    first = capture.run_child(sys.executable, {}, 10)
    second = capture.run_child(sys.executable, {}, 10)
    assert first["status"] == second["status"] == "ok"
    assert first["env"]["HOME"] == first["cwd"]
    assert first["cwd"] != second["cwd"]
    assert not Path(first["cwd"]).exists()
    assert "must-not-leak" not in json.dumps(first)
    assert "/private/personal/path" not in json.dumps(first)
    assert "motherduck_token" not in first["env"]


@pytest.mark.parametrize("body,status", [("import time; time.sleep(30)", "timeout"),
                                        ("import os, signal; os.kill(os.getpid(), signal.SIGKILL)", "crash"),
                                        ("raise RuntimeError('/private/token=secret')", "failed")])
def test_native_failure_and_timeout_do_not_leak_output(tmp_path, monkeypatch, body, status):
    fake = tmp_path / "fake.py"
    fake.write_text(body)
    monkeypatch.setattr(capture, "__file__", str(fake))
    result = capture.run_child(sys.executable, {}, 0.5)
    assert result["status"] == status
    assert "private" not in json.dumps(result)
    assert "secret" not in json.dumps(result)


def test_dependency_discovery_restarts_and_lock_never_discovers(monkeypatch):
    calls = []

    def run(python, spec, timeout):
        calls.append(json.loads(json.dumps(spec)))
        if len(calls) == 1:
            return {"status": "needs_dependency", "dependency": "avro", "phase": "load"}
        return {"status": "ok"}

    monkeypatch.setattr(capture, "run_child", run)
    base = {"engine": {"platform": "fixture"}, "functions": []}
    result = capture.collect_one("python", "iceberg", "core", base, 10)
    assert result["status"] == "ok"
    assert calls[0]["install_names"] == ["iceberg"]
    assert calls[1]["install_names"] == ["avro", "iceberg"]
    calls.clear()
    result = capture.collect_one("python", "iceberg", "core", base, 10,
                                 pin={"install_names": ["iceberg"], "load_names": ["iceberg"],
                                      "status": "ok", "artifacts": []})
    assert len(calls) == 1
    assert result["status"] == "failed"


def test_collection_requires_opt_in(tmp_path):
    with pytest.raises(SystemExit):
        capture.main(["collect", "--python", sys.executable, "--output", str(tmp_path / "out"), "--discover"])
    assert not (tmp_path / "out").exists()


def test_builtin_discovery_and_locked_replay(tmp_path):
    discovery, verified = tmp_path / "discovery", tmp_path / "verified"
    common = ["worker", "--allow-install", "--python", sys.executable, "--extension", "json"]
    assert capture.main([*common, "--output", str(discovery), "--discover"]) == 0
    assert capture.main([*common, "--output", str(verified), "--lock", str(discovery / "lock.json")]) == 0
    baseline = json.loads((verified / "base.json").read_text())
    snapshot = json.loads((verified / "json.json").read_text())
    assert snapshot["functions"] == {"added": [], "removed": [], "changed": []}
    assert snapshot["base_sha256"] == capture.digest(baseline)
    assert snapshot["mode"] == "verified"
    assert snapshot["artifacts"] == []
    assert baseline["engine"]["native_module_sha256"]
    assert all(row["schema_path"] for row in baseline["functions"])
    assert str(Path.home()) not in (verified / "json.json").read_text()
    lock = json.loads((discovery / "lock.json").read_text())
    lock["engine"]["source_id"] = "wrong-engine"
    capture.write_json(discovery / "wrong-lock.json", lock)
    assert capture.main([*common, "--output", str(tmp_path / "rejected"),
                         "--lock", str(discovery / "wrong-lock.json")]) == 1
    assert not (tmp_path / "rejected" / "json.json").exists()


def test_loaded_metadata_does_not_serialize_paths_or_installed_from():
    registry = [{"extension_name": "f", "extension_version": "123", "install_mode": "CUSTOM_PATH",
                 "loaded": True, "install_path": "/private/user", "installed_from": "https://secret@host"}]
    assert capture.loaded_rows(registry) == [{"name": "f", "version": "123", "install_mode": "CUSTOM_PATH"}]


@pytest.mark.parametrize("extension,bad_hash,expected", [("motherduck", False, "skipped"),
                                                        ("httpfs", True, "failed")])
def test_child_never_loads_motherduck_or_mismatched_installed_binary(tmp_path, monkeypatch,
                                                                  extension, bad_hash, expected):
    import audit_inventory

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CAPTURE_EXTENSIONS_CHILD", "1")
    commands = []
    engine = {"library_version": "fixture"}
    artifact = {"name": extension, "version": "fixture", "sha256": "0" * 64}
    binary = tmp_path / "fixture.duckdb_extension"
    binary.write_bytes(b"fixture")
    if not bad_hash:
        artifact["sha256"] = capture.file_digest(binary)

    class DB:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def execute(self, sql):
            commands.append(sql)

    monkeypatch.setitem(sys.modules, "duckdb", SimpleNamespace(connect=lambda **kwargs: DB()))
    monkeypatch.setattr(capture, "engine_identity", lambda *args: engine)
    monkeypatch.setattr(audit_inventory, "capture_functions", lambda db: [])
    monkeypatch.setattr(capture, "registry_rows", lambda db: [{
        "extension_name": extension, "aliases": [], "loaded": False,
        "extension_version": "fixture", "install_path": str(binary)}])
    monkeypatch.setattr(capture, "download", lambda *args: (binary, dict(artifact)))
    base = {"schema_version": capture.SCHEMA_VERSION, "capture_protocol": capture.CAPTURE_PROTOCOL,
            "snapshot_type": "base", "engine": engine,
            "loaded_extensions": [], "functions": []}
    request, response = tmp_path / "request.json", tmp_path / "response.json"
    capture.write_json(request, {"extension": extension, "install_names": [extension],
                                "load_names": [extension],
                                "base_sha256": capture.digest(base), "repository": "core"})
    capture.child(request, response)
    result = json.loads(response.read_text())
    assert result["status"] == expected
    assert commands == ["INSTALL " + capture.sql_string(binary)]
    assert str(tmp_path) not in response.read_text()
    if extension == "motherduck":
        assert result["error"]["code"] == "motherduck_load_requires_offline_review"


def test_matrix_continues_after_failure_and_retains_partial_lock(tmp_path, monkeypatch):
    base = {"engine": {"library_version": "fixture"}, "functions": []}
    monkeypatch.setattr(capture, "run_child", lambda *args: {"status": "ok", "base": base})
    calls = []

    def collect(python, extension, *args):
        calls.append(extension)
        return {"status": "timeout" if extension == "httpfs" else "ok", "artifacts": [],
                "install_names": [extension]}

    monkeypatch.setattr(capture, "collect_one", collect)
    output = tmp_path / "out"
    assert capture.main(["collect", "--allow-install", "--python", sys.executable, "--discover",
                         "--extension", "httpfs", "--extension", "json", "--output", str(output)]) == 1
    assert calls == ["httpfs", "json"]
    assert json.loads((output / "summary.json").read_text())["extensions"] == {"httpfs": "timeout", "json": "ok"}
    assert set(json.loads((output / "lock.json").read_text())["extensions"]) == {"httpfs", "json"}


def test_isolated_child_imports_never_write_bytecode_outside_home(tmp_path, monkeypatch):
    repo = tmp_path / "fixture-repository"
    repo.mkdir()
    module = repo / "uncached_capture_fixture.py"
    module.write_text("VALUE = 42\n")
    fake = repo / "worker.py"
    fake.write_text("import json, pathlib, sys\n"
                    "sys.path.insert(0, str(pathlib.Path(__file__).parent))\n"
                    "import uncached_capture_fixture\n"
                    "pathlib.Path(sys.argv[3]).write_text(json.dumps({'status':'ok',"
                    "'value':uncached_capture_fixture.VALUE, 'no_bytecode':sys.dont_write_bytecode}))\n")
    monkeypatch.setattr(capture, "__file__", str(fake))
    result = capture.run_child(sys.executable, {}, 10)
    assert result == {"status": "ok", "value": 42, "no_bytecode": True}
    assert sorted(path.name for path in repo.iterdir()) == [module.name, fake.name]
    assert not list(repo.rglob("*.pyc"))


def test_explicit_preloads_replay_in_order_with_distinct_stages(tmp_path):
    discovery, replay = tmp_path / "discovery", tmp_path / "replay"
    common = ["worker", "--allow-install", "--python", sys.executable, "--extension", "json"]
    assert capture.main([*common, "--output", str(discovery), "--discover",
                         "--preload", "json=icu", "--preload", "json=parquet"]) == 0
    lock = json.loads((discovery / "lock.json").read_text())
    pin = lock["extensions"]["json"]
    assert pin["load_names"] == ["icu", "parquet", "json"]
    assert pin["install_names"] == ["icu", "parquet", "json"]
    assert pin["artifacts"] == []  # Builtins are pinned by the engine hash.
    assert capture.main([*common, "--output", str(replay), "--lock", str(discovery / "lock.json")]) == 0
    result = json.loads((replay / "json.json").read_text())
    assert [stage["stage"] for stage in result["stages"]] == ["before", "dependency", "dependency", "target"]
    assert [stage["load_name"] for stage in result["stages"][1:]] == ["icu", "parquet", "json"]
    assert result["stages_sha256"] == pin["stages_sha256"]
    pin["load_names"] = ["parquet", "icu", "json"]
    capture.write_json(discovery / "reordered.json", lock)
    changed = tmp_path / "changed"
    assert capture.main([*common, "--output", str(changed), "--lock", str(discovery / "reordered.json")]) == 1
    assert json.loads((changed / "json.json").read_text())["error"]["code"] == "locked_stages_mismatch"
    # Install set alone is not capture equivalence: removing an explicit dependency
    # LOAD must fail even when that dependency was already linked into the engine.
    pin["load_names"] = ["icu", "json"]
    capture.write_json(discovery / "removed-preload.json", lock)
    removed = tmp_path / "removed"
    assert capture.main([*common, "--output", str(removed), "--lock", str(discovery / "removed-preload.json")]) == 1
    assert json.loads((removed / "json.json").read_text())["error"]["code"] == "locked_stages_mismatch"


def test_protocol_rejects_adapter_locks_and_spoofed_motherduck_success():
    lock = {"schema_version": capture.SCHEMA_VERSION, "capture_protocol": capture.CAPTURE_PROTOCOL,
            "extensions": {"motherduck": {"install_names": ["motherduck"], "load_names": ["motherduck"],
                                          "resolved_name": "motherduck", "status": "skipped", "stages_sha256": None}}}
    capture.validate_lock(lock, ["motherduck"])
    lock["extensions"]["motherduck"].update(status="ok", stages_sha256="spoof")
    with pytest.raises(ValueError, match="permitted staged"):
        capture.validate_lock(lock, ["motherduck"])
    lock["schema_version"] = 1
    with pytest.raises(ValueError, match="protocol v2"):
        capture.validate_lock(lock, ["motherduck"])
