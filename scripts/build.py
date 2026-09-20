import argparse
from pathlib import Path
import subprocess

from engine import add_engine_arguments, build_command, configure_command


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Configure and build the loadable extension against the pinned engine.")
    parser.add_argument("--jobs", type=int, default=4, help="parallel compile jobs (default 4)")
    parser.add_argument("--shell", action="store_true", help="also build the duckdb shell into the build directory")
    parser.add_argument("--build-dir", type=Path, default=root / "build/release",
                        help="CMake build directory (default build/release)")
    add_engine_arguments(parser)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    build = args.build_dir.resolve()
    subprocess.run(configure_command(args, build) + ["-DBUILD_SHELL=" + ("ON" if args.shell else "OFF")], check=True)
    targets = ["gatekeeper_loadable_extension"] + (["shell"] if args.shell else [])
    subprocess.run(build_command(build, targets, args.jobs), check=True)


if __name__ == "__main__":
    main()
