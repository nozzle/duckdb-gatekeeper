"""Build the linked SQL/typed-options fuzz target using a libFuzzer-capable Clang."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
from engine import add_engine_arguments, engine_cmake_flags, engine_source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=60)
    add_engine_arguments(parser)
    args = parser.parse_args()
    if args.seconds < 1:
        parser.error("--seconds must be positive")
    root = Path(__file__).resolve().parents[1]
    build = root / "build/sql-fuzz"
    subprocess.run(["cmake", "-G", "Ninja", "-S", str(engine_source(args)), "-B", str(build),
                    "-DPython3_EXECUTABLE=" + sys.executable,
                    "-DCMAKE_C_COMPILER=clang", "-DCMAKE_CXX_COMPILER=clang++", "-DCMAKE_BUILD_TYPE=Release",
                    *engine_cmake_flags(args), "-DBUILD_UNITTESTS=OFF", "-DBUILD_SHELL=OFF",
                    "-DDUCKDB_EXTENSION_CONFIGS=" + str(root / "extension_config.cmake"),
                    "-DGATEKEEPER_FUZZ=ON", "-DGATEKEEPER_SANITIZE=ON"], check=True)
    subprocess.run(["cmake", "--build", str(build), "--target", "gatekeeper_sql_fuzz", "--parallel", "4"], check=True)
    corpus = build / "corpus"
    corpus.mkdir(exist_ok=True)
    for i, query in enumerate(["SELECT 1", "SELECT * FROM t", "SELECT * FROM v", "SELECT * FROM secret.t",
                               "SELECT md5('x')", "DROP TABLE t", "WITH a AS (SELECT * FROM t) SELECT * FROM a",
                               "SELECT current_schema", "SELECT [1,2][1]", "SELECT {'a':1}.a", "SELECT NULL::INET",
                               "SELECT * FROM t WHERE x=? LIMIT $n", "SELECT 1 LIMIT len(repeat('x',200000000))",
                               "SELECT $1", "SELECT * FROM range($1)", "SELECT 1; SELECT 2",
                               "SELECT 1;", "SELECT ';'", "SELECT * FROM missing; DROP TABLE t",
                               "SELECT list_sum([1,2])", "SELECT list_sum($1)", "SELECT list_sum($1::INTEGER[])",
                               "SELECT list_unique($1)", "SELECT list_sort($1)", "SELECT unnest([1,2])",
                               "SELECT list_transform(['a'], lambda x: x COLLATE nocase = 'A')"]):
        (corpus / f"sql-{i}").write_bytes(bytes(4) + query.encode())
        (corpus / f"resolved-{i}").write_bytes(bytes([14,0,0,0]) + query.encode())
        for flags in range(16):
            (corpus / f"policy-{i}-{flags}").write_bytes(bytes([13,flags,0,0]) + query.encode())
    for mode in [1, 2, 15]:
        for option in range(6):
            for value in range(34):
                (corpus / f"option-{mode}-{option}-{value}").write_bytes(bytes([mode, option, value, 10]) + b"t")
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:detect_container_overflow=0"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    with (build / "fuzz.log").open("w") as log:
        result = subprocess.run([str(build / "extension/gatekeeper/gatekeeper_sql_fuzz"), str(corpus),
                                 "-max_total_time=" + str(args.seconds), "-max_len=4096", "-timeout=5",
                                 "-artifact_prefix=" + str(build) + "/"], env=env, stdout=log, stderr=log)
    for line in (build / "fuzz.log").read_text(errors="replace").splitlines():
        if "DONE" in line or line.startswith("Done ") or "ERROR:" in line or "SUMMARY:" in line:
            print(line)
    print("Full log:", build / "fuzz.log")
    result.check_returncode()


if __name__ == "__main__":
    main()
