"""Release surfaces consume canonical metadata or explicitly match its engine pin."""
import json
import re
import sys

from test_gatekeeper import ROOT, db

sys.path.insert(0, str(ROOT / "scripts"))
from versions import EXTENSION_VERSION, SUPPORTED_DUCKDB, SUPPORTED_DUCKDB_REVISION


def test_loaded_extension_version_matches_metadata(db):
    assert db.execute("SELECT extension_version FROM duckdb_extensions() WHERE extension_name='gatekeeper'").fetchone() == (EXTENSION_VERSION,)


def test_distribution_engine_pins():
    workflow = (ROOT / ".github/workflows/MainDistributionPipeline.yml").read_text()
    assert re.search(r"duckdb_version: v" + re.escape(SUPPORTED_DUCKDB) + r"\s", workflow)
    for path in ("Makefile", ".github/workflows/test.yml"):
        assert "OVERRIDE_GIT_DESCRIBE=v" + SUPPORTED_DUCKDB in (ROOT / path).read_text()
    assert f"duckdb=={SUPPORTED_DUCKDB}" in (ROOT / "requirements-dev.in").read_text().splitlines()
    assert f"version === 'v{SUPPORTED_DUCKDB}'" in (ROOT / "test/wasm/smoke.mjs").read_text()
    lock = json.loads((ROOT / "test/wasm/package-lock.json").read_text())
    package = json.loads((ROOT / "test/wasm/package.json").read_text())
    assert lock["packages"][""]["devDependencies"]["@duckdb/duckdb-wasm"] == package["devDependencies"]["@duckdb/duckdb-wasm"]
    descriptor = (ROOT / "community/description.yml").read_text()
    assert SUPPORTED_DUCKDB_REVISION in descriptor
