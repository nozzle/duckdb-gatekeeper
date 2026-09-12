import argparse
from pathlib import Path
import shutil
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--shell", action="store_true")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")

    def tool(name):
        local = root / ".venv/bin" / name
        found = str(local) if local.exists() else shutil.which(name)
        if not found:
            raise SystemExit(f"Missing {name}: install requirements-dev.txt first")
        return found

    cmake = tool("cmake")
    build = root / "build/release"
    subprocess.run([cmake, "-G", "Ninja", "-S", str(root / "duckdb"), "-B", str(build),
                    "-DCMAKE_MAKE_PROGRAM=" + tool("ninja"), "-DCMAKE_BUILD_TYPE=Release", "-DOVERRIDE_GIT_DESCRIBE=v1.5.5",
                    "-DDUCKDB_EXTENSION_CONFIGS=" + str(root / "extension_config.cmake"),
                    "-DBUILD_UNITTESTS=OFF", "-DBUILD_SHELL=" + ("ON" if args.shell else "OFF")], check=True)
    targets = ["gatekeeper_loadable_extension"] + (["shell"] if args.shell else [])
    subprocess.run([cmake, "--build", str(build), "--target", *targets, "--parallel", str(args.jobs)], check=True)


if __name__ == "__main__":
    main()
