"""Build the EH side module with the distribution pipeline's pinned Emscripten."""

import argparse
import json
import os
from pathlib import Path
import subprocess

from engine import add_engine_arguments, build_command, checkout_revision, engine_source, extension_cmake_flags

IMAGE = "emscripten/emsdk@sha256:96617f27fe16421588241def73908fd348a7f9d260440ed0d00b36dcf7a063cc"  # 6.0.9


def common_git_dir(checkout):
    return Path(subprocess.check_output(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=checkout, text=True
    ).strip())


def container_mounts(root, source):
    """Bind mounts (same path inside and out) for this checkout, the engine checkout, and their Git metadata.

    Linked worktrees and submodules keep their Git metadata outside the worktree. That holds for this
    checkout and, independently, for the selected engine even when its worktree sits under root (for
    example build/candidate-source linked from another clone); without it CMake stamps a dummy v0.0.1.
    """
    mounts, mounted = [], []

    def mount(path, options=""):
        if not any(path.is_relative_to(existing) for existing in mounted):
            mounts.extend(["-v", f"{path}:{path}{options}"])
            mounted.append(path)

    mount(root)
    mount(source)
    for checkout in (root, source):
        mount(common_git_dir(checkout), ":ro")
    return mounts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=4)
    add_engine_arguments(parser)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    root = Path(__file__).resolve().parents[1]
    source = engine_source(args)
    if args.duckdb_version is None:
        runtime = json.loads((root / "test/wasm/runtime.json").read_text())
        if checkout_revision(source) != runtime["engine_revision"]:
            parser.error("the default Wasm build requires the exact engine revision in test/wasm/runtime.json")
        args.duckdb_version = runtime["engine_version"]
    build = root / "build/wasm_eh"
    build.mkdir(parents=True, exist_ok=True)
    docker = ["docker", "run", "--rm", "--platform", "linux/amd64", "-w", str(root), *container_mounts(root, source)]
    # Preserve checkout ownership on Linux; Git rejects a runner-owned checkout as root.
    # The pinned SDK's prebuilt cache is read-only for this user.
    if hasattr(os, "getuid"):
        docker += ["--user", f"{os.getuid()}:{os.getgid()}"]
    docker += [IMAGE]
    # The container's Emscripten CMake, not this venv's; the extension flags are the same as every native build's.
    subprocess.run(docker + ["emcmake", "cmake", "-S", str(source), "-B", str(build), *extension_cmake_flags(args),
                            "-DDUCKDB_EXPLICIT_PLATFORM=wasm_eh", "-DWASM_LOADABLE_EXTENSIONS=1",
                            "-DBUILD_EXTENSIONS_ONLY=1",
                            "-DCMAKE_CXX_FLAGS=-fwasm-exceptions -DWEBDB_FAST_EXCEPTIONS=1"], check=True)
    subprocess.run(docker + build_command(build, ["gatekeeper_loadable_extension"], args.jobs, cmake="cmake"), check=True)


if __name__ == "__main__":
    main()
