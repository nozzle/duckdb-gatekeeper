"""Release surfaces consume canonical metadata or explicitly match its engine pin."""
import json
import os
import platform
import re
import subprocess

import duckdb
import pytest

from support.artifact import EXTENSION, ROOT, literal
from support.toolchain import repository
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
    # The browser smoke test asserts the runtime's embedded engine against the pin it reads from versions.cmake,
    # so the npm runtime pin is the only Wasm surface a repin edits by hand.
    smoke = (ROOT / "test/wasm/smoke.mjs").read_text()
    assert "versions.cmake" in smoke and "GATEKEEPER_DUCKDB_VERSION" in smoke
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
        db.execute("LOAD " + literal(tampered))
    with pytest.raises(duckdb.Error):
        db.execute("SELECT allowed FROM gatekeeper_validate('SELECT 1')")
    # A dev stamp of the same source commit (or a release stamp on a dev host) is a different footer identity
    # even though the compared field would agree; DuckDB distinguishes them and so must the guard.
    other_kind = version.replace("-dev", "") if not release else version + "-dev"
    (tmp_path / "kind").mkdir()
    kind = _tampered_artifact(tmp_path / "kind", other_kind, source_id)
    # Without the mismatch setting DuckDB's own footer check may refuse first; with it, the guard must.
    with pytest.raises(duckdb.Error, match="was built for DuckDB" if metadata_mismatch else None):
        duckdb.connect(config=config).execute("LOAD " + literal(kind))
    # The same copy/re-sign flow with the stamp left intact loads, so the refusals above are the guard.
    (tmp_path / "intact").mkdir()
    intact = _tampered_artifact(tmp_path / "intact", version, source_id)
    duckdb.connect(config=config).execute("LOAD " + literal(intact))


def test_check_engine_stamp_script():
    """The CI identity check derives the expectation from the engine checkout, not from a co-built shell. The
    distributed-artifact jobs have no engine checkout, so the source comparison is used only when one exists."""
    import check_engine_stamp
    from engine import checkout_revision
    version, source_id = _stamp(EXTENSION.read_bytes())
    arguments = ["--extension", str(EXTENSION)]
    if checkout_revision(ROOT / "duckdb"):
        arguments += ["--engine-source", str(ROOT / "duckdb")]
    assert check_engine_stamp.main(arguments + ["--expect-version", version]) == 0
    assert check_engine_stamp.main(arguments + ["--expect-version", version + "x"]) == 1
    with pytest.raises(SystemExit):
        check_engine_stamp.main(["--extension", str(ROOT / "versions.cmake"), "--expect-version", version])
    data = EXTENSION.read_bytes()
    assert check_engine_stamp.footer_field(data, 1) == "4"
    # DuckDB's footer holds the normalized version: the tag for releases, the source id for dev engines.
    assert check_engine_stamp.footer_field(data, 3) == (source_id if "-dev" in version else version)


def _synthetic_artifact(path, version, source_id, footer):
    """A blob with exactly the fields the checker reads: one Gatekeeper stamp and a DuckDB metadata footer."""
    fields = ["4", "linux_amd64", footer, EXTENSION_VERSION, "CPP", "", "", ""]
    body = b"\0code\0GATEKEEPER_BUILD_ENGINE %s %s\0\0\0more\0" % (version.encode(), source_id.encode())
    footer_bytes = b"".join(field.encode().ljust(32, b"\0") for field in reversed(fields)) + b"\0" * 256
    path.write_bytes(body + footer_bytes)
    return path


def test_check_engine_stamp_release_and_dev_footers(tmp_path):
    """Release footers carry the tag and dev footers the source id; both must match the stamp and the checkout."""
    import check_engine_stamp
    release_commit = repository(tmp_path / "release", tag="v1.5.5")
    dev_commit = repository(tmp_path / "dev", tag="v1.5.5", commits_after_tag=150)
    release = _synthetic_artifact(tmp_path / "release.duckdb_extension", "v1.5.5", release_commit[:10], "v1.5.5")
    dev = _synthetic_artifact(tmp_path / "dev.duckdb_extension", "v1.5.6-dev150", dev_commit[:10], dev_commit[:10])
    assert check_engine_stamp.check(release, tmp_path / "release", "v1.5.5") == []
    assert check_engine_stamp.check(dev, tmp_path / "dev") == []
    assert check_engine_stamp.check(dev, None, "v1.5.6-dev150") == []
    # A dev footer that carries the display version, or a release footer that carries a hash, is inconsistent.
    wrong = _synthetic_artifact(tmp_path / "wrong.duckdb_extension", "v1.5.6-dev150", dev_commit[:10], "v1.5.6-dev150")
    assert any("disagrees" in p for p in check_engine_stamp.check(wrong, tmp_path / "dev"))
    # The mislabeling this check exists to catch: a newer checkout stamped as the pinned release.
    mislabeled = _synthetic_artifact(tmp_path / "mislabeled.duckdb_extension", "v1.5.5", dev_commit[:10], "v1.5.5")
    problems = check_engine_stamp.check(mislabeled, tmp_path / "dev")
    assert any("-dev150" in p for p in problems), problems
    # Swapped checkouts fail on the source id.
    assert any("prefix" in p for p in check_engine_stamp.check(release, tmp_path / "dev"))
    assert any("requested" in p for p in check_engine_stamp.check(release, tmp_path / "release", "v1.5.6"))


def test_check_engine_stamp_accepts_the_pinned_shallow_checkout(tmp_path):
    """CI initializes the submodule shallow and tagless; the pinned revision is still identified by its commit,
    and only that revision. Any other undescribable checkout is refused rather than trusted."""
    import check_engine_stamp
    for name, revision in (("pinned", SUPPORTED_DUCKDB_REVISION), ("other", "f" * 40)):
        repository(tmp_path / name, head=revision)  # detached at the wanted id; no tags, no history
    pinned = _synthetic_artifact(tmp_path / "pinned.duckdb_extension", "v" + SUPPORTED_DUCKDB,
                                 SUPPORTED_DUCKDB_REVISION[:10], "v" + SUPPORTED_DUCKDB)
    assert check_engine_stamp.check(pinned, tmp_path / "pinned", "v" + SUPPORTED_DUCKDB) == []
    other = _synthetic_artifact(tmp_path / "other.duckdb_extension", "v" + SUPPORTED_DUCKDB, "f" * 10,
                                "v" + SUPPORTED_DUCKDB)
    with pytest.raises(SystemExit, match="cannot be described"):
        check_engine_stamp.check(other, tmp_path / "other")
    # An uninitialized submodule directory is not a checkout, even though it lives inside this repository.
    (tmp_path / "empty").mkdir()
    with pytest.raises(SystemExit, match="not a Git checkout"):
        check_engine_stamp.check(pinned, tmp_path / "empty")


def test_engine_guard_reads_the_builtin_engine_identity():
    """A host macro shadowing pragma_version() in the default catalog must not steer the load guard."""
    db = duckdb.connect(config={"allow_unsigned_extensions": "true"})
    db.execute("CREATE MACRO pragma_version() AS TABLE SELECT 'v0.0.0' AS library_version, 'shadow' AS source_id")
    assert db.execute("SELECT library_version FROM pragma_version()").fetchone() == ("v0.0.0",)
    db.execute("LOAD " + literal(EXTENSION))
    assert db.execute("SELECT allowed FROM gatekeeper_validate('SELECT 1')").fetchone() == (True,)
