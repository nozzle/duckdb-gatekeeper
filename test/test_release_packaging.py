"""Release assets must be complete, identifiable, and independently verifiable."""
import hashlib
import zipfile

import pytest

import package_release as release
from support.artifact import ROOT
from versions import EXTENSION_VERSION, SUPPORTED_DUCKDB, SUPPORTED_DUCKDB_REVISION

# The release the checkout describes; every expectation about names, tags, and drift is relative to it.
TAG = f"v{EXTENSION_VERSION}"
ENGINE_TAG = f"v{SUPPORTED_DUCKDB}"


@pytest.fixture
def artifacts(tmp_path):
    inputs = tmp_path / "artifacts"
    for platform in release.PLATFORMS:
        directory = inputs / f"gatekeeper-v{release.SUPPORTED_DUCKDB}-extension-{platform}"
        directory.mkdir(parents=True)
        suffix = ".wasm" if platform == "wasm_eh" else ""
        (directory / f"gatekeeper.duckdb_extension{suffix}").write_bytes(platform.encode())
    return inputs


@pytest.mark.parametrize("tag", [TAG, ""])
def test_release_archives_and_checksums(tag, artifacts, tmp_path):
    output = tmp_path / "release"
    release.package_release(tag, artifacts, output)
    lines = (output / "SHA256SUMS").read_text().splitlines()
    assert len(lines) == 10
    for line in lines:
        digest, name = line.split("  ")
        assert name.startswith(f"gatekeeper-{TAG}-duckdb-{ENGINE_TAG}-")
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
    directory = artifacts / f"gatekeeper-{ENGINE_TAG}-extension-windows_arm64"
    binary = directory / "gatekeeper.duckdb_extension"
    if damage == "missing_target":
        binary.unlink()
        directory.rmdir()
    elif damage == "empty_binary":
        binary.write_bytes(b"")
    elif damage == "extra_target":
        (artifacts / f"gatekeeper-{ENGINE_TAG}-extension-wasm_mvp").mkdir()
    elif damage == "extra_file":
        (directory / "unexpected.txt").write_text("unexpected")
    else:
        directory.rename(artifacts / "gatekeeper-v0.0.0-extension-windows_arm64")
    output = tmp_path / "release"
    with pytest.raises(ValueError):
        release.package_release(TAG, artifacts, output)
    assert not output.exists()


@pytest.mark.parametrize("tag", ["v0.0.0", EXTENSION_VERSION, TAG + "-rc1", ENGINE_TAG])
def test_wrong_release_tag_rejected(tag, artifacts, tmp_path):
    # Another release, the version without its v, a pre-release suffix, and the engine's tag in place of ours.
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
        release.package_release(TAG, artifacts, output)
    assert existing.read_text() == "previous release"


def test_output_file_is_not_overwritten(artifacts, tmp_path):
    output = tmp_path / "release"
    output.write_text("existing file")
    with pytest.raises(ValueError, match="Output must be empty and a directory"):
        release.package_release(TAG, artifacts, output)
    assert output.read_text() == "existing file"


@pytest.mark.parametrize("filename,old,new,message", [
    ("versions.cmake", f'GATEKEEPER_VERSION "{EXTENSION_VERSION}"', 'GATEKEEPER_VERSION "0.0.9"', "must agree"),
    ("versions.cmake", f'GATEKEEPER_DUCKDB_VERSION "{SUPPORTED_DUCKDB}"', 'GATEKEEPER_DUCKDB_VERSION "0.0.9"',
     "must agree"),
    ("versions.cmake", f'GATEKEEPER_VERSION "{EXTENSION_VERSION}"', 'GATEKEEPER_VERSION "garbage"', "Invalid version"),
    ("community/description.yml", f"version: {EXTENSION_VERSION}", "version: 0.0.9", "Community descriptor.*must agree"),
    ("community/description.yml", f"ref: {TAG}", "ref: v0.0.9", "Community descriptor.*must agree"),
    ("community/description.yml", f"version: {EXTENSION_VERSION}", f"other_version: {EXTENSION_VERSION}",
     "extension.version"),
    ("community/description.yml", f"ref: {TAG}", f"other_ref: {TAG}", "repo.ref"),
    ("community/description.yml", "repo:\n", "other_repo:\n", "repo.ref"),
    ("community/description.yml", SUPPORTED_DUCKDB_REVISION, "0" * 40, "must cite the pinned DuckDB"),
    ("community/description.yml", f"DuckDB {SUPPORTED_DUCKDB}", "DuckDB 0.0.9", "must cite the pinned DuckDB"),
])
def test_source_version_drift_is_diagnostic(tmp_path, monkeypatch, filename, old, new, message):
    for source in ("versions.cmake", "community/description.yml"):
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        text = (ROOT / source).read_text()
        if source == filename:
            assert old in text
            text = text.replace(old, new)
        target.write_text(text)
    monkeypatch.setattr(release, "ROOT", tmp_path)
    with pytest.raises(ValueError, match=message):
        release.release_version(TAG)
