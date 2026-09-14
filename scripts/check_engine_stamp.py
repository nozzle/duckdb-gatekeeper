"""Check a built loadable's recorded engine identity against the engine checkout it was built from.

DuckDB stamps ``duckdb_version`` into the artifact footer and Gatekeeper additionally bakes a
``GATEKEEPER_BUILD_ENGINE <version> <source_id>`` stamp (scripts/generate.py). A shell built in the same
CMake invocation carries the same labels, so loading the artifact into that shell cannot detect a
mislabeled build. This script derives the expected identity from the checkout's own Git metadata, the
way DuckDB's CMakeLists.txt does without an override, and fails when either stamp disagrees.

    python scripts/check_engine_stamp.py --extension build/release/extension/gatekeeper/gatekeeper.duckdb_extension \
        --engine-source duckdb [--expect-version v1.5.6]

``--expect-version`` pins the release version the caller knows the engine to be (for example the tag the
community pipeline requested). At least one of ``--engine-source`` and ``--expect-version`` is required;
without a checkout only the footer, the Gatekeeper stamp, and the expected version are compared.
"""
import argparse
from pathlib import Path
import re
import subprocess
import sys

STAMP = re.compile(rb"GATEKEEPER_BUILD_ENGINE ([^\s\0]+) ([^\s\0]+)\0")
# scripts/append_metadata.cmake: eight 32-byte fields appended in reverse order, then a 256-byte signature.
FOOTER_SIZE = 8 * 32 + 256


def footer_field(data: bytes, index: int) -> str:
    """Metadata field ``index`` (1-based, as numbered in append_metadata.cmake)."""
    end = len(data) - 256 - (index - 1) * 32
    return data[end - 32:end].rstrip(b"\0").decode()


def git(source: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(source), *arguments], text=True).strip()


def expected_identity(source: Path):
    """(version, full commit) DuckDB derives from ``git describe`` when no override is supplied."""
    commit = git(source, "rev-parse", "HEAD")
    describe = git(source, "describe", "--tags", "--long", "--match", "v*")
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)-(\d+)-g[0-9a-f]+", describe)
    if not match:
        raise SystemExit(f"unexpected git describe output: {describe}")
    major, minor, patch, iteration = (int(group) for group in match.groups())
    if iteration == 0:
        return f"v{major}.{minor}.{patch}", commit
    # Dev builds bump the patch (or the minor under MAIN_BRANCH_VERSIONING); only the -devN suffix and the
    # source id are compared for them.
    return f"-dev{iteration}", commit


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--extension", type=Path, required=True)
    parser.add_argument("--engine-source", type=Path, default=None, help="engine checkout the artifact was built from")
    parser.add_argument("--expect-version", default=None, help="release version the engine must identify as")
    args = parser.parse_args(argv)
    if args.engine_source is None and args.expect_version is None:
        parser.error("at least one of --engine-source and --expect-version is required")

    data = args.extension.read_bytes()
    if len(data) < FOOTER_SIZE or footer_field(data, 1) != "4":
        raise SystemExit("no DuckDB metadata footer found")
    footer_version = footer_field(data, 3)
    stamps = STAMP.findall(data)
    if len(stamps) != 1:
        raise SystemExit(f"expected exactly one GATEKEEPER_BUILD_ENGINE stamp, found {len(stamps)}")
    stamp_version, stamp_source = (field.decode() for field in stamps[0])

    problems = []
    if stamp_version != footer_version:
        problems.append(f"Gatekeeper stamp {stamp_version} disagrees with the footer duckdb_version {footer_version}")
    if args.engine_source is not None:
        expected_version, commit = expected_identity(args.engine_source)
        if not commit.startswith(stamp_source):
            problems.append(f"Gatekeeper stamp source id {stamp_source} is not a prefix of the checkout commit {commit}")
        if expected_version.startswith("-dev"):
            if not footer_version.endswith(expected_version):
                problems.append(f"footer duckdb_version {footer_version} is not the dev build {expected_version} of the checkout")
        elif footer_version != expected_version:
            problems.append(f"footer duckdb_version {footer_version} does not match the checkout tag {expected_version}")
    if args.expect_version and footer_version != args.expect_version:
        problems.append(f"footer duckdb_version {footer_version} is not the requested {args.expect_version}")
    for problem in problems:
        print("::error::" + problem, file=sys.stderr)
    if not problems:
        against = f", matching {args.engine_source}" if args.engine_source is not None else ""
        print(f"{args.extension}: built for DuckDB {footer_version} ({stamp_source}){against}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
