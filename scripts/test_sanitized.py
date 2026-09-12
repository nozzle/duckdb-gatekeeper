"""Build and run Gatekeeper ASan/UBSan tests on macOS/Linux."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]

    def tool(name):
        local = root / ".venv/bin" / name
        found = str(local) if local.exists() else shutil.which(name)
        if not found:
            raise SystemExit(f"Missing {name}")
        return found

    build = root / "build/sanitized"
    subprocess.run([tool("cmake"), "-G", "Ninja", "-S", str(root / "duckdb"), "-B", str(build),
                    "-DCMAKE_MAKE_PROGRAM=" + tool("ninja"), "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                    "-DDUCKDB_EXTENSION_CONFIGS=" + str(root / "extension_config.cmake"),
                    "-DBUILD_UNITTESTS=OFF", "-DBUILD_SHELL=OFF", "-DGATEKEEPER_SANITIZE=ON"], check=True)
    subprocess.run([tool("cmake"), "--build", str(build), "--target", "gatekeeper_loadable_extension", "--parallel", "4"], check=True)
    env = os.environ.copy()
    env["GATEKEEPER_EXTENSION"] = str(build / "extension/gatekeeper/gatekeeper.duckdb_extension")
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    if platform.system() == "Darwin":
        runtime = subprocess.check_output(["clang", "-print-file-name=libclang_rt.asan_osx_dynamic.dylib"], text=True).strip()
        env["DYLD_INSERT_LIBRARIES"] = runtime
    elif platform.system() == "Linux":
        runtime = subprocess.check_output([os.environ.get("CC", "cc"), "-print-file-name=libasan.so"], text=True).strip()
        env["LD_PRELOAD"] = runtime
    else:
        raise SystemExit("Sanitizer runner supports macOS/Linux only")
    if not Path(runtime).is_file():
        raise SystemExit("Cannot locate compiler's ASan runtime")
    subprocess.run([sys.executable, "-m", "pytest", "test", "-q"], cwd=root, env=env, check=True)


if __name__ == "__main__":
    main()
