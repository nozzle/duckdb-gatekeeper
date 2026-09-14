"""Shared engine-checkout selection for the local build scripts.

DuckDB stamps the engine identity from ``git describe`` of the checkout it compiles. A shallow
clone of the pinned submodule cannot describe itself, and DuckDB then stamps a dummy ``v0.0.1``
artifact that no real engine will load, so the release pin is supplied for exactly the pinned
revision. Any other checkout, including the submodule directory with another revision checked
out, defaults to its own Git metadata; a fixed default would label it as the pinned release.
"""
import argparse
from pathlib import Path
import subprocess

from versions import SUPPORTED_DUCKDB, SUPPORTED_DUCKDB_REVISION

ROOT = Path(__file__).resolve().parents[1]


def add_engine_arguments(parser: argparse.ArgumentParser):
    parser.add_argument("--duckdb-source", type=Path, default=ROOT / "duckdb",
                        help="DuckDB source checkout to build (default: the pinned submodule)")
    parser.add_argument("--duckdb-version", default=None,
                        help="OVERRIDE_GIT_DESCRIBE value, e.g. v1.5.4; defaults to the release pin when the "
                             "checkout is at the pinned revision and to its own git describe otherwise")


def engine_source(args):
    return args.duckdb_source.resolve()


def checkout_revision(source: Path):
    """The commit checked out at ``source``, or None when ``source`` is not itself a Git checkout.

    An uninitialized submodule directory is empty but sits inside this repository, so Git would otherwise
    discover the parent checkout and report Gatekeeper's own commit as the engine revision.
    """
    source = Path(source)
    if not source.is_dir():
        return None
    try:
        toplevel = subprocess.run(["git", "-C", str(source), "rev-parse", "--show-toplevel"], capture_output=True,
                                  text=True)
        if toplevel.returncode != 0 or Path(toplevel.stdout.strip()).resolve() != source.resolve():
            return None
        result = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True)
    except OSError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def engine_version(args):
    """Return the OVERRIDE_GIT_DESCRIBE value, or None to let DuckDB describe the checkout."""
    if args.duckdb_version is not None:
        return args.duckdb_version or None
    if checkout_revision(engine_source(args)) == SUPPORTED_DUCKDB_REVISION:
        return "v" + SUPPORTED_DUCKDB
    return None


def engine_cmake_flags(args):
    """Always set the cache entry: an omitted -D leaves a previous override in CMakeCache.txt."""
    return ["-DOVERRIDE_GIT_DESCRIBE=" + (engine_version(args) or "")]
