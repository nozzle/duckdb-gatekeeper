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
