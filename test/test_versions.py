"""Release surfaces consume canonical metadata or explicitly match its engine pin."""
import json
import os
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
    # The Makefile supplies the release pin only for the pinned engine revision and reads both values from
    # versions.cmake; an unconditional default would label every community rebuild as the pinned release.
    makefile = (ROOT / "Makefile").read_text()
    assert "GATEKEEPER_DUCKDB_REVISION" in makefile and "GATEKEEPER_DUCKDB_VERSION" in makefile
    assert not re.search(r"^OVERRIDE_GIT_DESCRIBE \?=", makefile, re.M)
    assert "v" + SUPPORTED_DUCKDB not in makefile
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
    build_version, build_source_id = _stamp(EXTENSION.read_bytes())
    assert build_version == version
    # Release artifacts are accepted on the version tag; Git abbreviation lengths may differ from the host's.
    if "-dev" in version:
        assert build_source_id == source_id
    # CMake generates into the extension's binary dir, next to the artifact, for every build configuration.
    header = EXTENSION.parent / "generated/version.hpp"
    if os.getenv("GATEKEEPER_EXTENSION") and not header.is_file():
        pytest.skip("distributed artifact under test has no build tree beside it")
    assert header.is_file(), header
    assert f'] = "GATEKEEPER_BUILD_ENGINE {build_version} {build_source_id}"' in header.read_text()


def test_review_provenance_is_separate_from_release_pin(tmp_path):
    assert BASELINE_FILENAME == f"duckdb-{REVIEWED_DUCKDB}.json"
    assert (ROOT / "inventories/baselines" / BASELINE_FILENAME).is_file()
    (tmp_path / "inventories").mkdir()
    (tmp_path / "inventories/core.json").write_text(json.dumps({"reviewed_duckdb": "1.4.0"}))
    assert reviewed_duckdb(tmp_path) == "1.4.0"
    for malformed in ({"reviewed_duckdb": "v1.4"}, {"reviewed_duckdb": 1.4}, {"reviewed_duckdb": None}, {}):
        (tmp_path / "inventories/core.json").write_text(json.dumps(malformed))
        with pytest.raises(ValueError, match="reviewed_duckdb"):
            reviewed_duckdb(tmp_path)


# The stamp array is NUL padded (scripts/generate.py STAMP_WIDTH), so include the run of NULs that follows
# and any in-place rewrite of a different length can keep the total byte count.
STAMP = re.compile(rb"GATEKEEPER_BUILD_ENGINE ([^\s\0]+) ([^\s\0]+)\0+")


def _stamp(data):
    """The (version, source_id) the artifact records for itself; the fields of the build tree, not the host."""
    matches = STAMP.findall(data)
    assert len(matches) == 1, "expected exactly one build engine stamp"
    return tuple(field.decode() for field in matches[0])


def _tampered_artifact(tmp_path, version, source_id):
    """Copy the built loadable with its build engine stamp rewritten in place, keeping the byte count."""
    data = EXTENSION.read_bytes()
    match = STAMP.search(data)
    assert match and len(STAMP.findall(data)) == 1
    replacement = b"GATEKEEPER_BUILD_ENGINE %s %s" % (version.encode(), source_id.encode())
    assert len(replacement) < match.end() - match.start(), "rewritten stamp does not fit the padded array"
    replacement = replacement.ljust(match.end() - match.start(), b"\0")
    # DuckDB derives the entrypoint symbol from the file name, so the copy keeps it.
    tampered = tmp_path / EXTENSION.name
    tampered.write_bytes(data[:match.start()] + replacement + data[match.end():])
    if platform.system() == "Darwin":
        # The kernel kills a process that pages in code whose ad-hoc signature no longer matches. Re-sign the
        # Mach-O image (which ends at LC_CODE_SIGNATURE) and re-append DuckDB's trailing metadata footer.
        listing = subprocess.check_output(["otool", "-l", str(tampered)], text=True)
        signature = listing[listing.index("LC_CODE_SIGNATURE"):]
        end = sum(int(re.search(rf"{field}\s+(\d+)", signature)[1]) for field in ("dataoff", "datasize"))
        image, footer = tampered.read_bytes()[:end], tampered.read_bytes()[end:]
        tampered.write_bytes(image)
        subprocess.run(["codesign", "--force", "--sign", "-", str(tampered)], check=True, capture_output=True)
        tampered.write_bytes(tampered.read_bytes() + footer)
    return tampered


@pytest.mark.parametrize("metadata_mismatch", [False, True])
def test_engine_guard_refuses_a_different_engine(tmp_path, metadata_mismatch):
    """An artifact whose recorded build engine disagrees with the host must be refused by Gatekeeper itself,
    whether or not DuckDB's footer check is disabled with allow_extensions_metadata_mismatch."""
    # Start from the artifact's own stamp: a release build is accepted on its version tag alone, so its
    # source id may legitimately be abbreviated differently from what the host reports.
    version, source_id = _stamp(EXTENSION.read_bytes())
    release = "-dev" not in version
    # Release builds are identified by the version tag, dev builds by the source id; alter only the field
    # the guard compares and expect it, formatted as the guard prints it, in the diagnostic.
    altered = version if release else source_id
    altered = altered[:-1] + ("0" if altered[-1] != "0" else "1")
    tampered = _tampered_artifact(tmp_path, *((altered, source_id) if release else (version, altered)))
    expected = rf"was built for DuckDB {re.escape(altered)} \(" if release else rf"\({re.escape(altered)}\); this engine"
    config = {"allow_unsigned_extensions": "true", "allow_extensions_metadata_mismatch": str(metadata_mismatch).lower()}
    db = duckdb.connect(config=config)
    with pytest.raises(duckdb.InvalidInputException, match=expected):
        db.execute("LOAD '" + str(tampered).replace("'", "''") + "'")
    with pytest.raises(duckdb.Error):
        db.execute("SELECT allowed FROM gatekeeper_validate('SELECT 1')")
    # A dev stamp of the same source commit (or a release stamp on a dev host) is a different footer identity
    # even though the compared field would agree; DuckDB distinguishes them and so must the guard.
    other_kind = version.replace("-dev", "") if not release else version + "-dev"
    (tmp_path / "kind").mkdir()
    kind = _tampered_artifact(tmp_path / "kind", other_kind, source_id)
    # Without the mismatch setting DuckDB's own footer check may refuse first; with it, the guard must.
    with pytest.raises(duckdb.Error, match="was built for DuckDB" if metadata_mismatch else None):
        duckdb.connect(config=config).execute("LOAD '" + str(kind).replace("'", "''") + "'")
    # The same copy/re-sign flow with the stamp left intact loads, so the refusals above are the guard.
    (tmp_path / "intact").mkdir()
    intact = _tampered_artifact(tmp_path / "intact", version, source_id)
    duckdb.connect(config=config).execute("LOAD '" + str(intact).replace("'", "''") + "'")


def test_check_engine_stamp_script():
    """The CI identity check derives the expectation from the engine checkout, not from a co-built shell."""
    import check_engine_stamp
    version, source_id = _stamp(EXTENSION.read_bytes())
    arguments = ["--extension", str(EXTENSION), "--engine-source", str(ROOT / "duckdb")]
    if "-dev" in version:
        pytest.skip("local artifact was built from an unpinned engine checkout")
    assert check_engine_stamp.main(arguments + ["--expect-version", version]) == 0
    with pytest.raises(SystemExit):
        check_engine_stamp.main(["--extension", str(ROOT / "versions.cmake"), "--engine-source", str(ROOT / "duckdb")])
    assert check_engine_stamp.main(arguments + ["--expect-version", version + "-dev1"]) == 1
    data = EXTENSION.read_bytes()
    assert check_engine_stamp.footer_field(data, 3) == version
    assert check_engine_stamp.footer_field(data, 1) == "4"


def test_engine_guard_reads_the_builtin_engine_identity():
    """A host macro shadowing pragma_version() in the default catalog must not steer the load guard."""
    db = duckdb.connect(config={"allow_unsigned_extensions": "true"})
    db.execute("CREATE MACRO pragma_version() AS TABLE SELECT 'v0.0.0' AS library_version, 'shadow' AS source_id")
    assert db.execute("SELECT library_version FROM pragma_version()").fetchone() == ("v0.0.0",)
    db.execute("LOAD '" + str(EXTENSION).replace("'", "''") + "'")
    assert db.execute("SELECT allowed FROM gatekeeper_validate('SELECT 1')").fetchone() == (True,)
