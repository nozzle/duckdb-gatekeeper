"""Check a built loadable's recorded engine identity against the engine it was built from.

DuckDB stamps the *normalized* engine version into footer field 3 (``extension_build_tools.cmake``,
``DUCKDB_NORMALIZED_VERSION``): the version tag for release engines and the abbreviated source id for
dev engines. Gatekeeper additionally bakes ``GATEKEEPER_BUILD_ENGINE <version> <source_id>``
(scripts/generate.py). A shell built in the same CMake invocation carries the same labels, so loading
the artifact into that shell cannot detect a mislabeled build. This script derives the expectation
from the engine checkout's own Git metadata instead and fails when the stamps disagree with it.

    python scripts/check_engine_stamp.py --extension build/release/extension/gatekeeper/gatekeeper.duckdb_extension \\
        --engine-source duckdb [--expect-version v1.5.6]

``--engine-source`` must be the checkout that was compiled. The display version is derived the way the
engine's CMakeLists.txt derives it (DuckDB 2.0 from its release version file and commit count, 1.5 from
``git describe``); the pinned release revision in versions.cmake is expected as the pinned release, as
the build labels it. ``--expect-version`` additionally pins the display version the caller knows the engine
to be, and is the only confirmation of a prerelease label (``-alphaN``, ``-rcN``), which a build is given
explicitly rather than deriving. At least one of the two is required; without a checkout only the footer,
the Gatekeeper stamp, and the expected version are compared.
"""
import argparse
from pathlib import Path
import re
import subprocess
import sys

from engine import checkout_revision
from versions import SUPPORTED_DUCKDB, SUPPORTED_DUCKDB_REVISION

STAMP = re.compile(rb"GATEKEEPER_BUILD_ENGINE ([^\s\0]+) ([^\s\0]+)\0")
# scripts/append_metadata.cmake: eight 32-byte fields appended in reverse order, then a 256-byte signature.
FOOTER_SIZE = 8 * 32 + 256


def footer_field(data: bytes, index: int) -> str:
    """Metadata field ``index`` (1-based, as numbered in append_metadata.cmake)."""
    end = len(data) - 256 - (index - 1) * 32
    return data[end - 32:end].rstrip(b"\0").decode()


def describe(source: Path):
    """``git describe --tags --long`` of the checkout, or None when it has no reachable tag."""
    result = subprocess.run(["git", "-C", str(source), "describe", "--tags", "--long", "--match", "v*"],
                            capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def commit_count(source: Path):
    """``git rev-list --count HEAD`` of the checkout, or None when Git cannot count it."""
    result = subprocess.run(["git", "-C", str(source), "rev-list", "--count", "HEAD"], capture_output=True, text=True)
    return int(result.stdout.strip()) if result.returncode == 0 else None


def expected_version(source: Path, commit: str):
    """The display version DuckDB derives for the checkout, as Gatekeeper's build passes it.

    The pinned release revision is always built as the pinned release (Makefile, scripts/engine.py pass
    OVERRIDE_GIT_DESCRIBE). Otherwise DuckDB 2.0 (CMakeLists.txt, DUCKDB_RELEASE_VERSION_FILE) labels every
    build ``v<release>.0-dev<commit count>`` from ``scripts/ci/release_version.txt``, and DuckDB 1.5 describes
    the checkout from its tags: ``vX.Y.Z`` for a tagged release commit and ``-devN`` (suffix only: the bumped
    component depends on MAIN_BRANCH_VERSIONING) for other commits. A 1.5 checkout that cannot describe itself
    is refused.
    """
    if commit == SUPPORTED_DUCKDB_REVISION:
        return "v" + SUPPORTED_DUCKDB
    release_file = source / "scripts/ci/release_version.txt"
    if release_file.exists():
        release = release_file.read_text().strip()
        count = commit_count(source)
        if not re.fullmatch(r"\d+\.\d+", release) or count is None:
            raise SystemExit(f"{source} has an unreadable release version or commit count")
        return f"v{release}.0-dev{count}"
    described = describe(source)
    if described is None:
        raise SystemExit(f"{source} cannot be described (shallow or tagless checkout) and is not the pinned "
                         f"release revision {SUPPORTED_DUCKDB_REVISION}")
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)-(\d+)-g[0-9a-f]+", described)
    if not match:
        raise SystemExit(f"unexpected git describe output: {described}")
    major, minor, patch, iteration = (int(group) for group in match.groups())
    return f"v{major}.{minor}.{patch}" if iteration == 0 else f"-dev{iteration}"


def check(extension: Path, engine_source=None, expect_version=None):
    """Return the list of problems (empty when the artifact's identity is consistent and expected)."""
    data = extension.read_bytes()
    if len(data) < FOOTER_SIZE or footer_field(data, 1) != "4":
        raise SystemExit("no DuckDB metadata footer found")
    footer = footer_field(data, 3)
    stamps = STAMP.findall(data)
    if len(stamps) != 1:
        raise SystemExit(f"expected exactly one GATEKEEPER_BUILD_ENGINE stamp, found {len(stamps)}")
    version, source_id = (field.decode() for field in stamps[0])
    release = "-dev" not in version

    problems = []
    # DuckDB's footer identity is the tag for releases and the source id for dev builds; the stamp must agree.
    normalized = version if release else source_id
    if footer != normalized:
        problems.append(f"footer duckdb_version {footer} disagrees with the Gatekeeper stamp "
                        f"({version}, {source_id}); DuckDB would have written {normalized}")
    if engine_source is not None:
        commit = checkout_revision(engine_source)
        if commit is None:
            raise SystemExit(f"{engine_source} is not a Git checkout")
        if not commit.startswith(source_id):
            problems.append(f"stamp source id {source_id} is not a prefix of the checkout commit {commit}")
        if re.search(r"-(alpha|rc)\d+$", version):
            # A prerelease label is never derived from a checkout: DuckDB's build is given it explicitly (the
            # nightly Python packages, for one, are v2.0.0-alphaN), so the caller must name it, and the
            # checkout is held to the source id alone.
            if version != expect_version:
                problems.append(f"stamp version {version} is a prerelease label the checkout cannot confirm; "
                                "pass it with --expect-version")
        else:
            expected = expected_version(engine_source, commit)
            if expected.startswith("-dev"):
                if release or not version.endswith(expected):
                    problems.append(f"stamp version {version} is not the {expected} build of the checkout")
            elif version != expected:
                problems.append(f"stamp version {version} does not match the checkout's release {expected}")
    if expect_version and version != expect_version:
        problems.append(f"stamp version {version} is not the requested {expect_version}")
    if not problems:
        against = f", matching {engine_source}" if engine_source is not None else ""
        print(f"{extension}: built for DuckDB {version} ({source_id}), footer {footer}{against}")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--extension", type=Path, required=True)
    parser.add_argument("--engine-source", type=Path, default=None, help="engine checkout the artifact was built from")
    parser.add_argument("--expect-version", default=None, help="display version the engine must identify as")
    args = parser.parse_args(argv)
    if args.engine_source is None and args.expect_version is None:
        parser.error("at least one of --engine-source and --expect-version is required")
    problems = check(args.extension, args.engine_source, args.expect_version)
    for problem in problems:
        print("::error::" + problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
