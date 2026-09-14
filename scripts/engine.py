"""Shared engine-checkout selection for the local build scripts.

Release builds compile the pinned ``duckdb`` submodule and stamp it with the release pin so that
shallow clones, which cannot ``git describe`` the engine, do not produce a dummy ``v0.0.1``
artifact that no real engine will load. Any other checkout defaults to its own Git metadata.
"""
import argparse
from pathlib import Path

from versions import SUPPORTED_DUCKDB

ROOT = Path(__file__).resolve().parents[1]


def add_engine_arguments(parser: argparse.ArgumentParser):
    parser.add_argument("--duckdb-source", type=Path, default=ROOT / "duckdb",
                        help="DuckDB source checkout to build (default: the pinned submodule)")
    parser.add_argument("--duckdb-version", default=None,
                        help="OVERRIDE_GIT_DESCRIBE value, e.g. v1.5.4; defaults to the release pin for the "
                             "submodule and to the checkout's own git describe otherwise")


def engine_source(args):
    return args.duckdb_source.resolve()


def engine_version(args):
    """Return the OVERRIDE_GIT_DESCRIBE value, or None to let DuckDB describe the checkout."""
    if args.duckdb_version is not None:
        return args.duckdb_version or None
    if engine_source(args) == (ROOT / "duckdb").resolve():
        return "v" + SUPPORTED_DUCKDB
    return None


def engine_cmake_flags(args):
    """Always set the cache entry: an omitted -D leaves a previous override in CMakeCache.txt."""
    return ["-DOVERRIDE_GIT_DESCRIBE=" + (engine_version(args) or "")]
