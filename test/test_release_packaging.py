"""Release assets must be complete, identifiable, and independently verifiable."""
import hashlib
from pathlib import Path
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import package_release as release


@pytest.fixture
def artifacts(tmp_path):
    inputs = tmp_path / "artifacts"
    for platform in release.PLATFORMS:
        directory = inputs / f"gatekeeper-v{release.SUPPORTED_DUCKDB}-extension-{platform}"
        directory.mkdir(parents=True)
        suffix = ".wasm" if platform == "wasm_eh" else ""
        (directory / f"gatekeeper.duckdb_extension{suffix}").write_bytes(platform.encode())
    return inputs


@pytest.mark.parametrize("tag", ["v0.1.0", ""])
def test_release_archives_and_checksums(tag, artifacts, tmp_path):
    output = tmp_path / "release"
    release.package_release(tag, artifacts, output)
    lines = (output / "SHA256SUMS").read_text().splitlines()
    assert len(lines) == 10
    for line in lines:
        digest, name = line.split("  ")
        assert name.startswith("gatekeeper-v0.1.0-duckdb-v1.5.5-")
        assert name.endswith("-unsigned.zip")
        archive = output / name
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == digest
        with zipfile.ZipFile(archive) as bundle:
            binary = "gatekeeper.duckdb_extension" + (".wasm" if "wasm_eh" in name else "")
            assert set(bundle.namelist()) == {binary, "LICENSE", "NOTICE"}
            assert bundle.read(binary).decode() in release.PLATFORMS
            assert bundle.read("NOTICE") == (ROOT / "NOTICE").read_bytes()
            assert bundle.read("LICENSE") == (ROOT / "LICENSE").read_bytes()
    assert "unsigned development binaries" in (output / "RELEASE_NOTES.md").read_text()


@pytest.mark.parametrize("damage", ["missing_target", "empty_binary", "extra_target", "extra_file", "wrong_engine"])
def test_incomplete_or_unexpected_distribution_rejected(artifacts, tmp_path, damage):
    directory = artifacts / "gatekeeper-v1.5.5-extension-windows_arm64"
    binary = directory / "gatekeeper.duckdb_extension"
    if damage == "missing_target":
        binary.unlink()
        directory.rmdir()
    elif damage == "empty_binary":
        binary.write_bytes(b"")
    elif damage == "extra_target":
        (artifacts / "gatekeeper-v1.5.5-extension-wasm_mvp").mkdir()
    elif damage == "extra_file":
        (directory / "unexpected.txt").write_text("unexpected")
    else:
        directory.rename(artifacts / "gatekeeper-v1.5.6-extension-windows_arm64")
    output = tmp_path / "release"
    with pytest.raises(ValueError):
        release.package_release("v0.1.0", artifacts, output)
    assert not output.exists()


@pytest.mark.parametrize("tag", ["v0.2.0", "0.1.0", "v0.1.0-rc1", "v1.5.5"])
def test_wrong_release_tag_rejected(tag, artifacts, tmp_path):
    output = tmp_path / "release"
    with pytest.raises(ValueError, match="must agree"):
        release.package_release(tag, artifacts, output)
    assert not output.exists()


def test_existing_assets_are_not_overwritten(artifacts, tmp_path):
    output = tmp_path / "release"
    output.mkdir()
    existing = output / "SHA256SUMS"
    existing.write_text("previous release")
    with pytest.raises(ValueError, match="Output must be empty"):
        release.package_release("v0.1.0", artifacts, output)
    assert existing.read_text() == "previous release"


def test_output_file_is_not_overwritten(artifacts, tmp_path):
    output = tmp_path / "release"
    output.write_text("existing file")
    with pytest.raises(ValueError, match="Output must be empty and a directory"):
        release.package_release("v0.1.0", artifacts, output)
    assert output.read_text() == "existing file"


@pytest.mark.parametrize("filename,old,new,message", [
    ("extension_config.cmake", "EXTENSION_VERSION", "OTHER_VERSION", "extension_config.cmake"),
    ("src/gatekeeper_extension.cpp", "Version()", "OtherVersion()", "Version"),
    ("src/gatekeeper_extension.cpp", "Gatekeeper 0.1.0 supports", "Gatekeeper supports", "load-error message"),
    ("src/gatekeeper_extension.cpp", "Gatekeeper 0.1.0 supports", "Gatekeeper 0.0.9 supports", "must agree"),
    ("src/gatekeeper_extension.cpp", 'SUPPORTED_DUCKDB_VERSION = "v1.5.5"',
     'SUPPORTED_DUCKDB_VERSION = "v1.5.4"', r"C\+\+ engine pin.*must agree"),
    ("community/description.yml", "version: 0.1.0", "version: 0.0.9", "Community descriptor.*must agree"),
    ("community/description.yml", "ref: v0.1.0", "ref: v0.0.9", "Community descriptor.*must agree"),
    ("community/description.yml", "version: 0.1.0", "other_version: 0.1.0", "extension.version"),
    ("community/description.yml", "ref: v0.1.0", "other_ref: v0.1.0", "repo.ref"),
    ("community/description.yml", "repo:\n", "other_repo:\n", "repo.ref"),
    ("community/description.yml", release.SUPPORTED_DUCKDB_REVISION, "0" * 40, "must cite the pinned DuckDB"),
    ("community/description.yml", "DuckDB 1.5.5", "DuckDB 1.5.4", "must cite the pinned DuckDB"),
])
def test_source_version_drift_is_diagnostic(tmp_path, monkeypatch, filename, old, new, message):
    for source in ("extension_config.cmake", "src/gatekeeper_extension.cpp", "community/description.yml"):
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        text = (ROOT / source).read_text()
        if source == filename:
            assert old in text
            text = text.replace(old, new)
        target.write_text(text)
    monkeypatch.setattr(release, "ROOT", tmp_path)
    with pytest.raises(ValueError, match=message):
        release.release_version("v0.1.0")
