"""Release surfaces consume canonical metadata or explicitly match its engine pin."""
import json
import platform
import re
import subprocess
import sys

import duckdb
import pytest

from test_gatekeeper import EXTENSION, ROOT, db

sys.path.insert(0, str(ROOT / "scripts"))
from versions import (BASELINE_FILENAME, EXTENSION_VERSION, REVIEWED_DUCKDB, SUPPORTED_DUCKDB,
                      SUPPORTED_DUCKDB_REVISION, load_versions, reviewed_duckdb)


def test_metadata_whitespace_and_comments(tmp_path):
    lines = (ROOT / "versions.cmake").read_text().splitlines()
    (tmp_path / "versions.cmake").write_text("\n".join("  " + line + "  # note" for line in lines) + "\n")
    assert load_versions(tmp_path) == load_versions()


def test_loaded_extension_version_matches_metadata(db):
    assert db.execute("SELECT extension_version FROM duckdb_extensions() WHERE extension_name='gatekeeper'").fetchone() == (EXTENSION_VERSION,)


def test_distribution_engine_pins():
    workflow = (ROOT / ".github/workflows/MainDistributionPipeline.yml").read_text()
    assert re.search(r"duckdb_version: v" + re.escape(SUPPORTED_DUCKDB) + r"\s", workflow)
    assert "OVERRIDE_GIT_DESCRIBE=v" + SUPPORTED_DUCKDB in (ROOT / ".github/workflows/test.yml").read_text()
    # Overridable default: shallow clones cannot describe the engine and would otherwise stamp v0.0.1.
    assert re.search(r"^OVERRIDE_GIT_DESCRIBE \?= v" + re.escape(SUPPORTED_DUCKDB) + r"$",
                     (ROOT / "Makefile").read_text(), re.M)
    assert f"duckdb=={SUPPORTED_DUCKDB}" in (ROOT / "requirements-dev.in").read_text().splitlines()
    assert f"version === 'v{SUPPORTED_DUCKDB}'" in (ROOT / "test/wasm/smoke.mjs").read_text()
    lock = json.loads((ROOT / "test/wasm/package-lock.json").read_text())
    package = json.loads((ROOT / "test/wasm/package.json").read_text())
    assert lock["packages"][""]["devDependencies"]["@duckdb/duckdb-wasm"] == package["devDependencies"]["@duckdb/duckdb-wasm"]
    descriptor = (ROOT / "community/description.yml").read_text()
    assert SUPPORTED_DUCKDB_REVISION in descriptor


def test_engine_guard_uses_build_engine(db):
    """The artifact under test is stamped with the engine that just accepted it, and the stamp is inspectable."""
    version, source_id = db.execute("PRAGMA version").fetchone()[:2]
    stamp = re.search(rb"GATEKEEPER_BUILD_ENGINE (\S+) (\S+)\0", EXTENSION.read_bytes())
    assert stamp, "build engine stamp missing from the artifact"
    assert stamp[1].decode() == version
    if "-dev" in version:
        assert stamp[2].decode() == source_id
    header = EXTENSION.parent / "generated/version.hpp"
    if header.is_file():
        assert f'BUILD_ENGINE_STAMP[] = "GATEKEEPER_BUILD_ENGINE {version} ' in header.read_text()


def test_review_provenance_is_separate_from_release_pin(tmp_path):
    assert BASELINE_FILENAME == f"duckdb-{REVIEWED_DUCKDB}.json"
    assert (ROOT / "inventories/baselines" / BASELINE_FILENAME).is_file()
    (tmp_path / "inventories").mkdir()
    (tmp_path / "inventories/core.json").write_text(json.dumps({"reviewed_duckdb": "1.4.0"}))
    assert reviewed_duckdb(tmp_path) == "1.4.0"
    (tmp_path / "inventories/core.json").write_text(json.dumps({"reviewed_duckdb": "v1.4"}))
    with pytest.raises(ValueError, match="reviewed_duckdb"):
        reviewed_duckdb(tmp_path)


def _tampered_artifact(tmp_path, old, new):
    """Copy the built loadable with its build engine stamp rewritten in place (same length)."""
    data = EXTENSION.read_bytes()
    needle, replacement = b"GATEKEEPER_BUILD_ENGINE " + old.encode(), b"GATEKEEPER_BUILD_ENGINE " + new.encode()
    assert len(needle) == len(replacement)
    assert data.count(needle) == 1
    # DuckDB derives the entrypoint symbol from the file name, so the copy keeps it.
    tampered = tmp_path / EXTENSION.name
    tampered.write_bytes(data.replace(needle, replacement))
    if platform.system() == "Darwin":
        # The kernel kills a process that pages in code whose ad-hoc signature no longer matches. Re-sign the
        # Mach-O image (which ends at LC_CODE_SIGNATURE) and re-append DuckDB's trailing metadata footer.
        listing = subprocess.check_output(["otool", "-l", str(tampered)], text=True)
        signature = listing[listing.index("LC_CODE_SIGNATURE"):]
        end = sum(int(re.search(rf"{field} (\d+)", signature)[1]) for field in ("dataoff", "datasize"))
        image, footer = tampered.read_bytes()[:end], tampered.read_bytes()[end:]
        tampered.write_bytes(image)
        subprocess.run(["codesign", "--force", "--sign", "-", str(tampered)], check=True, capture_output=True)
        tampered.write_bytes(tampered.read_bytes() + footer)
    return tampered


@pytest.mark.parametrize("metadata_mismatch", [False, True])
def test_engine_guard_refuses_a_different_engine(tmp_path, metadata_mismatch):
    """An artifact whose recorded build engine disagrees with the host must be refused by Gatekeeper itself,
    whether or not DuckDB's footer check is disabled with allow_extensions_metadata_mismatch."""
    version, source_id = duckdb.connect().execute("PRAGMA version").fetchone()[:2]
    release = "-dev" not in version
    # Release builds are identified by the version tag, dev builds by the source id.
    old = version if release else f"{version} {source_id}"
    new = old[:-1] + ("0" if old[-1] != "0" else "1")
    tampered = _tampered_artifact(tmp_path, old, new)
    config = {"allow_unsigned_extensions": "true", "allow_extensions_metadata_mismatch": str(metadata_mismatch).lower()}
    db = duckdb.connect(config=config)
    with pytest.raises(duckdb.InvalidInputException, match=rf"was built for DuckDB .*{re.escape(new)}"):
        db.execute("LOAD '" + str(tampered).replace("'", "''") + "'")
    with pytest.raises(duckdb.Error):
        db.execute("SELECT allowed FROM gatekeeper_validate('SELECT 1')")
    # The same copy/re-sign flow with the stamp left intact loads, so the refusal above is the guard.
    (tmp_path / "intact").mkdir()
    intact = _tampered_artifact(tmp_path / "intact", old, old)
    duckdb.connect(config=config).execute("LOAD '" + str(intact).replace("'", "''") + "'")
