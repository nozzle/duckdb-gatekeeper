import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--shell", action="store_true")
    parser.add_argument("--duckdb-source", type=Path, default=root / "duckdb")
    parser.add_argument("--build-dir", type=Path, default=root / "build/release")
    parser.add_argument("--duckdb-version", help="optional engine version override, e.g. v1.5.4")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")

    def tool(name):
        found = shutil.which(name, path=os.pathsep.join([str(root / ".venv/bin"), str(root / ".venv/Scripts"),
                                                         os.environ.get("PATH", "")]))
        if not found:
            raise SystemExit(f"Missing {name}: install requirements-dev.txt first")
        return found

    cmake = tool("cmake")
    build = args.build_dir.resolve()
    version = ["-DOVERRIDE_GIT_DESCRIBE=" + (args.duckdb_version or "")]
    subprocess.run([cmake, "-G", "Ninja", "-S", str(args.duckdb_source.resolve()), "-B", str(build),
                    "-DPython3_EXECUTABLE=" + sys.executable,
                    "-DCMAKE_MAKE_PROGRAM=" + tool("ninja"), "-DCMAKE_BUILD_TYPE=Release", *version,
                    "-DDUCKDB_EXTENSION_CONFIGS=" + str(root / "extension_config.cmake"),
                    "-DBUILD_UNITTESTS=OFF", "-DBUILD_SHELL=" + ("ON" if args.shell else "OFF")], check=True)
    targets = ["gatekeeper_loadable_extension"] + (["shell"] if args.shell else [])
    subprocess.run([cmake, "--build", str(build), "--target", *targets, "--parallel", str(args.jobs)], check=True)


if __name__ == "__main__":
    main()
