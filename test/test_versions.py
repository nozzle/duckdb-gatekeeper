"""Release surfaces consume canonical metadata or explicitly match its engine pin."""
import json
import re
import sys

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
    """The loaded artifact carries the engine it was built from, and that engine accepted it."""
    version = db.execute("PRAGMA version").fetchone()
    header = EXTENSION.parent / "generated/version.hpp"
    if not header.is_file():
        pytest.skip("generated headers are not next to the extension under test")
    text = header.read_text()
    assert f'BUILD_DUCKDB_VERSION = "{version[0]}"' in text
    if "-dev" in version[0]:
        assert f'BUILD_DUCKDB_SOURCE_ID = "{version[1]}"' in text


def test_review_provenance_is_separate_from_release_pin(tmp_path):
    assert BASELINE_FILENAME == f"duckdb-{REVIEWED_DUCKDB}.json"
    assert (ROOT / "inventories/baselines" / BASELINE_FILENAME).is_file()
    (tmp_path / "inventories").mkdir()
    (tmp_path / "inventories/core.json").write_text(json.dumps({"reviewed_duckdb": "1.4.0"}))
    assert reviewed_duckdb(tmp_path) == "1.4.0"
    (tmp_path / "inventories/core.json").write_text(json.dumps({"reviewed_duckdb": "v1.4"}))
    with pytest.raises(ValueError, match="reviewed_duckdb"):
        reviewed_duckdb(tmp_path)
