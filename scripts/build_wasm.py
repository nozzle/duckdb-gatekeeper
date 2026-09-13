"""Build the EH side module with the distribution pipeline's pinned Emscripten."""

import argparse
from pathlib import Path
import subprocess

from versions import SUPPORTED_DUCKDB

IMAGE = "emscripten/emsdk@sha256:9922c93314b63a1d9ceba2e76f03737f1f9cc4b7350341211e2d3555633ffdd5"  # 3.1.71


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    root = Path(__file__).resolve().parents[1]
    build = root / "build/wasm_eh"
    build.mkdir(parents=True, exist_ok=True)
    common = Path(subprocess.check_output(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=root, text=True
    ).strip())
    docker = ["docker", "run", "--rm", "--platform", "linux/amd64", "-v", f"{root}:{root}", "-w", str(root)]
    # Linked worktrees and their submodules refer to metadata outside the worktree.
    if not common.is_relative_to(root):
        docker += ["-v", f"{common}:{common}:ro"]
    docker += [IMAGE]
    subprocess.run(docker + ["emcmake", "cmake", "-S", "duckdb", "-B", str(build),
                            "-DDUCKDB_EXTENSION_CONFIGS=" + str(root / "extension_config.cmake"),
                            "-DCMAKE_BUILD_TYPE=Release", "-DOVERRIDE_GIT_DESCRIBE=v" + SUPPORTED_DUCKDB,
                            "-DDUCKDB_EXPLICIT_PLATFORM=wasm_eh", "-DWASM_LOADABLE_EXTENSIONS=1",
                            "-DBUILD_EXTENSIONS_ONLY=1", "-DBUILD_UNITTESTS=OFF",
                            "-DCMAKE_CXX_FLAGS=-fwasm-exceptions -DWEBDB_FAST_EXCEPTIONS=1"], check=True)
    subprocess.run(docker + ["cmake", "--build", str(build), "--target", "gatekeeper_loadable_extension",
                            "--parallel", str(args.jobs)], check=True)


if __name__ == "__main__":
    main()
