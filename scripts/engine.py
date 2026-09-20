"""Engine-checkout selection and the CMake invocation the local build scripts share.

DuckDB stamps the engine identity from ``git describe`` of the checkout it compiles. A shallow
clone of the pinned submodule cannot describe itself, and DuckDB then stamps a dummy ``v0.0.1``
artifact that no real engine will load, so the release pin is supplied for exactly the pinned
revision. Any other checkout, including the submodule directory with another revision checked
out, defaults to its own Git metadata; a fixed default would label it as the pinned release.

Every configuration of this extension is a DuckDB source build with ``extension_config.cmake``
adding Gatekeeper (``extension_cmake_flags``); native builds additionally use this venv's CMake,
Ninja and Python (``configure_command``). What differs between the scripts stays in them: build
type, sanitizer and fuzzer options, shell and unittest targets, and the Emscripten container.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

from versions import SUPPORTED_DUCKDB, SUPPORTED_DUCKDB_REVISION

ROOT = Path(__file__).resolve().parents[1]


def tool(name):
    """A build tool installed next to the running interpreter (the venv requirements-dev.txt was installed
    into, wherever it is: this checkout's .venv, a CI setup-python environment, the fuzz image's /opt venv)
    or, failing that, on PATH. The interpreter's directory comes first so a checkout mounted into a container
    does not hand the container its host's launchers."""
    found = shutil.which(name, path=os.pathsep.join([str(Path(sys.executable).parent), os.environ.get("PATH", "")]))
    if not found:
        raise SystemExit(f"Missing {name}: install requirements-dev.txt first")
    return found


def add_engine_arguments(parser: argparse.ArgumentParser):
    parser.add_argument("--duckdb-source", type=Path, default=ROOT / "duckdb",
                        help="DuckDB source checkout to build (default: the pinned submodule)")
    parser.add_argument("--duckdb-version", default=None,
                        help="OVERRIDE_GIT_DESCRIBE value, e.g. v1.6.0; defaults to the release pin when the "
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


def extension_cmake_flags(args, build_type="Release"):
    """The flags every configuration of this extension passes, in a container or not: the build type, the
    engine label, the extension config that adds Gatekeeper to the engine build, and no engine unit tests."""
    return ["-DCMAKE_BUILD_TYPE=" + build_type, *engine_cmake_flags(args),
            "-DDUCKDB_EXTENSION_CONFIGS=" + str(ROOT / "extension_config.cmake"), "-DBUILD_UNITTESTS=OFF"]


def configure_command(args, build_dir, build_type="Release"):
    """The configure command of a native build: this venv's CMake generating Ninja files for this venv's
    Ninja, generation running under this interpreter, plus ``extension_cmake_flags``."""
    return [tool("cmake"), "-G", "Ninja", "-S", str(engine_source(args)), "-B", str(build_dir),
            "-DPython3_EXECUTABLE=" + sys.executable, "-DCMAKE_MAKE_PROGRAM=" + tool("ninja"),
            *extension_cmake_flags(args, build_type)]


def build_command(build_dir, targets, jobs, cmake=None):
    """``cmake --build`` of ``targets``; ``cmake`` names another CMake (a container's) than this venv's."""
    return [cmake or tool("cmake"), "--build", str(build_dir), "--target", *targets, "--parallel", str(jobs)]
