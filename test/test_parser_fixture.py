"""Alternative parser fixtures are immutable, host-matched inputs, never floating INSTALL results."""
import gzip
import hashlib
import io
import json
import re

import pytest

import prepare_test_parser as parser
from versions import SUPPORTED_DUCKDB, SUPPORTED_DUCKDB_REVISION


@pytest.fixture
def pinned(monkeypatch, tmp_path):
    fields = ["4", "osx_arm64", "v2.0.0", "bcdf276132", "CPP", "", "", ""]
    binary = b"parser fixture\0" + b"".join(v.encode().ljust(32, b"\0") for v in reversed(fields)) + b"\0" * 256
    archive = gzip.compress(binary)
    pin = {"extension": "legacy_parser", "extension_version": "bcdf276132", "platforms": {
        "osx_arm64": {"archive_sha256": hashlib.sha256(archive).hexdigest(),
                      "binary_sha256": hashlib.sha256(binary).hexdigest()}}}
    path = tmp_path / "cache/legacy_parser.duckdb_extension"
    parser.checked_path.cache_clear()
    monkeypatch.setattr(parser, "fixture", lambda: ("2.0.0", "osx_arm64", pin, path))
    yield path, binary, archive, pin
    parser.checked_path.cache_clear()


def test_verified_download_and_offline_load_path(pinned, monkeypatch):
    path, binary, archive, _ = pinned
    requests = []

    def download(request, timeout):
        requests.append(request.full_url)
        return io.BytesIO(archive)

    monkeypatch.setattr(parser.urllib.request, "urlopen", download)
    assert parser.prepare() == path and path.read_bytes() == binary
    assert requests == ["https://extensions.duckdb.org/v2.0.0/osx_arm64/legacy_parser.duckdb_extension.gz"]
    monkeypatch.setattr(parser.urllib.request, "urlopen", lambda *a, **k: pytest.fail("cached fixtures must stay offline"))
    assert parser.prepare() == parser.checked_path("legacy_parser") == path


def test_mutated_download_is_not_written(pinned, monkeypatch):
    path, _, archive, _ = pinned
    monkeypatch.setattr(parser.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(archive + b"changed"))
    with pytest.raises(RuntimeError, match="download checksum"):
        parser.prepare()
    assert not path.exists()


def test_mutated_cache_is_refused_and_preserved(pinned):
    path, binary, _, _ = pinned
    path.parent.mkdir()
    path.write_bytes(binary + b"changed")
    for read in [parser.prepare, lambda: parser.checked_path("legacy_parser")]:
        with pytest.raises(RuntimeError, match="binary checksum"):
            read()
    assert path.read_bytes() == binary + b"changed"


@pytest.mark.parametrize("field,value", [(2, "linux_amd64"), (3, "v1.5.6"), (4, "other")])
def test_wrong_host_or_revision_is_refused_even_with_matching_hash(pinned, field, value):
    path, binary, _, pin = pinned
    end = len(binary) - 256 - (field - 1) * 32
    changed = binary[:end - 32] + value.encode().ljust(32, b"\0") + binary[end:]
    pin["platforms"]["osx_arm64"]["binary_sha256"] = hashlib.sha256(changed).hexdigest()
    with pytest.raises(RuntimeError, match="metadata mismatch"):
        parser.verify(changed, "2.0.0", "osx_arm64", pin)
    assert not path.exists()


def test_missing_fixture_never_installs_during_tests(pinned, monkeypatch):
    monkeypatch.setattr(parser.urllib.request, "urlopen", lambda *a, **k: pytest.fail("unexpected download"))
    with pytest.raises(RuntimeError, match="prepare_test_parser.py"):
        parser.checked_path("legacy_parser")


def test_parser_pins_cover_the_supported_python_hosts():
    pins = json.loads(parser.PINS.read_text())
    assert pins[SUPPORTED_DUCKDB]["engine_revision"] == SUPPORTED_DUCKDB_REVISION
    hosts = {"linux_amd64", "linux_arm64", "osx_amd64", "osx_arm64", "windows_amd64", "windows_arm64"}
    for version, pin in pins.items():
        assert re.fullmatch(r"[0-9a-f]{40}", pin["engine_revision"])
        assert re.fullmatch(r"[0-9a-f]{40}", pin["revision"])
        if pin["extension_version"] == "v" + version:
            assert pin["revision"] == pin["engine_revision"]  # In-tree autocomplete.
        else:
            assert pin["extension_version"] == pin["revision"][:10]
        assert set(pin["platforms"]) == hosts
        for hashes in pin["platforms"].values():
            assert set(hashes) == {"archive_sha256", "binary_sha256"}
            assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values())
