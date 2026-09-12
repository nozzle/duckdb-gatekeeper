"""Build the linked SQL/typed-options fuzz target using a libFuzzer-capable Clang."""
import argparse
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=60)
    args = parser.parse_args()
    if args.seconds < 1:
        parser.error("--seconds must be positive")
    root = Path(__file__).resolve().parents[1]
    build = root / "build/sql-fuzz"
    subprocess.run(["cmake", "-G", "Ninja", "-S", str(root / "duckdb"), "-B", str(build),
                    "-DCMAKE_C_COMPILER=clang", "-DCMAKE_CXX_COMPILER=clang++", "-DCMAKE_BUILD_TYPE=Release",
                    "-DOVERRIDE_GIT_DESCRIBE=v1.5.5", "-DBUILD_UNITTESTS=OFF", "-DBUILD_SHELL=OFF",
                    "-DDUCKDB_EXTENSION_CONFIGS=" + str(root / "extension_config.cmake"),
                    "-DGATEKEEPER_FUZZ=ON", "-DGATEKEEPER_SANITIZE=ON"], check=True)
    subprocess.run(["cmake", "--build", str(build), "--target", "gatekeeper_sql_fuzz", "--parallel", "4"], check=True)
    corpus = build / "corpus"
    corpus.mkdir(exist_ok=True)
    for i, query in enumerate(["SELECT 1", "SELECT * FROM t", "SELECT * FROM v", "SELECT * FROM secret.t",
                               "SELECT md5('x')", "DROP TABLE t", "WITH a AS (SELECT * FROM t) SELECT * FROM a"]):
        (corpus / str(i)).write_bytes(b"\0" + query.encode())
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    with (build / "fuzz.log").open("w") as log:
        result = subprocess.run([str(build / "extension/gatekeeper/gatekeeper_sql_fuzz"), str(corpus),
                                 "-max_total_time=" + str(args.seconds), "-max_len=4096", "-timeout=5",
                                 "-artifact_prefix=" + str(build) + "/"], env=env, stdout=log, stderr=log)
    for line in (build / "fuzz.log").read_text().splitlines():
        if "DONE" in line or line.startswith("Done ") or "ERROR:" in line or "SUMMARY:" in line:
            print(line)
    print("Full log:", build / "fuzz.log")
    result.check_returncode()


if __name__ == "__main__":
    main()
