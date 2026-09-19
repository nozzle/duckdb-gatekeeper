"""Build and run Gatekeeper ASan/UBSan tests on macOS/Linux.

Clang is required on both platforms and is selected explicitly (override with CC/CXX only to point
at a different Clang). GCC's -fsanitize instrumentation odr-uses the ``static constexpr``
LogicalType members and emits definitions that collide with the out-of-line ones DuckDB keeps in
types.cpp when linking against libduckdb_static.a, so a GCC configuration is refused up front.
"""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys
from engine import add_engine_arguments, build_command, configure_command, engine_version
from sanitize import environment
from versions import SUPPORTED_DUCKDB


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    add_engine_arguments(parser)
    args = parser.parse_args()
    # The instrumented loadable is exercised inside the pinned duckdb Python package, whose footer check and
    # Gatekeeper's own engine guard refuse an artifact built for any other engine. An alternate checkout is
    # only usable here when it really is that release; other engines need scripts/build.py plus their own host.
    if engine_version(args) != "v" + SUPPORTED_DUCKDB:
        parser.error(f"the sanitized suite runs in the pinned duckdb=={SUPPORTED_DUCKDB} Python package; "
                     f"pass --duckdb-version v{SUPPORTED_DUCKDB} only for a checkout of that release")

    cc = os.environ.get("CC", "clang")
    cxx = os.environ.get("CXX", "clang++")
    for compiler in (cc, cxx):
        try:
            version = subprocess.run([compiler, "--version"], capture_output=True, text=True)
        except OSError:
            raise SystemExit(f"Missing {compiler}; the sanitized build requires Clang (see module docstring)")
        if version.returncode != 0 or "clang" not in version.stdout.lower():
            raise SystemExit(f"{compiler} is not Clang; the sanitized build requires Clang (see module docstring)")
    build = root / "build/sanitized"
    subprocess.run(configure_command(args, build, "RelWithDebInfo") +
                   ["-DCMAKE_C_COMPILER=" + cc, "-DCMAKE_CXX_COMPILER=" + cxx, "-DBUILD_SHELL=OFF",
                    "-DGATEKEEPER_SANITIZE=ON"], check=True)
    subprocess.run(build_command(build, ["gatekeeper_loadable_extension"], 4), check=True)
    # The instrumented loadable runs inside the uninstrumented Python package.
    env = environment(mixed_runtime=True)
    env["GATEKEEPER_EXTENSION"] = str(build / "extension/gatekeeper/gatekeeper.duckdb_extension")
    if platform.system() == "Darwin":
        runtime = subprocess.check_output([cc, "-print-file-name=libclang_rt.asan_osx_dynamic.dylib"], text=True).strip()
        env["DYLD_INSERT_LIBRARIES"] = runtime
    elif platform.system() == "Linux":
        # Clang's shared ASan runtime also carries the UBSan handlers the extension references.
        library = "libclang_rt.asan-" + platform.machine() + ".so"
        runtime = subprocess.check_output([cc, "-print-file-name=" + library], text=True).strip()
        env["LD_PRELOAD"] = runtime
    else:
        raise SystemExit("Sanitizer runner supports macOS/Linux only")
    if not Path(runtime).is_file():
        raise SystemExit("Cannot locate compiler's ASan runtime")
    subprocess.run([sys.executable, "-m", "pytest", "test", "-q"], cwd=root, env=env, check=True)


if __name__ == "__main__":
    main()
