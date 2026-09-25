"""Build the linked SQL/typed/JSON-options fuzz target using a libFuzzer-capable Clang."""
import argparse
from pathlib import Path
import subprocess
from engine import add_engine_arguments, build_command, configure_command
from sanitize import environment, run_libfuzzer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=60)
    add_engine_arguments(parser)
    args = parser.parse_args()
    if args.seconds < 1:
        parser.error("--seconds must be positive")
    root = Path(__file__).resolve().parents[1]
    build = root / "build/sql-fuzz"
    subprocess.run(configure_command(args, build) +
                   ["-DCMAKE_C_COMPILER=clang", "-DCMAKE_CXX_COMPILER=clang++", "-DBUILD_SHELL=OFF",
                    "-DGATEKEEPER_FUZZ=ON", "-DGATEKEEPER_SANITIZE=ON"], check=True)
    subprocess.run(build_command(build, ["gatekeeper_sql_fuzz"], 4), check=True)
    corpus = build / "corpus"
    corpus.mkdir(exist_ok=True)
    for i, query in enumerate(["SELECT 1", "SELECT * FROM t", "SELECT * FROM v", "SELECT * FROM secret.t",
                               "SELECT md5('x')", "DROP TABLE t", "WITH a AS (SELECT * FROM t) SELECT * FROM a",
                               "SELECT current_schema", "SELECT [1,2][1]", "SELECT {'a':1}.a", "SELECT NULL::INET",
                               "SELECT * FROM t WHERE x=? LIMIT $n", "SELECT 1 LIMIT len(repeat('x',20000000))",
                               "SELECT $1", "SELECT * FROM range($1)", "SELECT 1; SELECT 2",
                               "SELECT 1;", "SELECT ';'", "SELECT * FROM missing; DROP TABLE t",
                               "SELECT list_sum([1,2])", "SELECT list_sum($1)", "SELECT list_sum($1::INTEGER[])",
                               "SELECT list_unique($1)", "SELECT list_sort($1)", "SELECT unnest([1,2])",
                               "SELECT list_transform(['a'], lambda x: x COLLATE nocase = 'A')"]):
        (corpus / f"sql-{i}").write_bytes(bytes(4) + query.encode())
        (corpus / f"resolved-{i}").write_bytes(bytes([14,0,0,0]) + query.encode())
        (corpus / f"enforced-{i}").write_bytes(bytes([12,0,0,0]) + query.encode())
        for flags in range(16):
            (corpus / f"policy-{i}-{flags}").write_bytes(bytes([13,flags,0,0]) + query.encode())
    for mode in [1, 2, 15]:
        for option in range(7):
            for value in range(34):
                (corpus / f"option-{mode}-{option}-{value}").write_bytes(bytes([mode, option, value, 10]) + b"t")
    for i, document in enumerate([
        '{"version":2,"options":{}}',
        '{"version":2,"options":{"allowed_tables":[]}}',
        '{"version":2,"options":{"allowed_tables":[{"catalog":null,"schema_path":["main"],"table":"t"}]}}',
        '{"version":2,"options":{"allowed_tables":[{"schema_path":["finance","*"],"table":"t"}]}}',
        '{"version":2,"options":{"use_default_functions":false,"allowed_functions":[{"catalog":"system","schema_path":["main"],"name":"abs"}],"blocked_functions":["md5"]}}',
        '{"version":2,"options":{"blocked_functions":[],"blocked_functions":["md5"]}}',
        '{"version":2,"options":{"blocked_tables":[{"schema_path":["main"],"table":"t","extra":1}]}}',
    ]):
        for mode in [1, 15]:
            (corpus / f"json-{mode}-{i}").write_bytes(bytes([mode, 5, 0, 10]) + document.encode())
    # The instrumented extension and harness link the uninstrumented engine library.
    run_libfuzzer(build / "extension/gatekeeper/gatekeeper_sql_fuzz", corpus, build / "fuzz.log", args.seconds,
                  max_len=4096, env=environment(mixed_runtime=True))


if __name__ == "__main__":
    main()
