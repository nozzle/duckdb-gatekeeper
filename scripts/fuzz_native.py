"""Coverage-guided native AST/policy fuzzing using clang libFuzzer and ASan/UBSan."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from sanitize import environment, run_libfuzzer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=60)
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    root = Path(__file__).resolve().parents[1]
    out = root / "build/fuzz"
    out.mkdir(parents=True, exist_ok=True)
    generated = out / "generated"
    subprocess.run([sys.executable, str(root / "scripts/generate.py"), "--output", str(generated)], check=True)
    corpus = out / "ast-corpus"
    corpus.mkdir(exist_ok=True)
    import duckdb
    with duckdb.connect() as db:
        for i, query in enumerate(["SELECT 1", "SELECT md5('x')", "SELECT * FROM private.t",
                                   "WITH t AS (SELECT 1) SELECT * FROM t", "SELECT * FROM range(3)",
                                   "WITH RECURSIVE t AS (SELECT 1 n UNION ALL SELECT n+1 FROM t WHERE n<3) SELECT * FROM t",
                                   "SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT md5('x')",
                                   "SELECT NULL::STRUCT(x INTEGER, y INET[])", "SELECT [1,2][1]",
                                   "SELECT current_schema", "SELECT 'x' COLLATE de",
                                   "SELECT 1 LIMIT len(repeat('x',20000000))", "SELECT * FROM range($1)",
                                   "SELECT quantile_cont(x,[0.2,0.8]) FROM t"]):
            ast = json.loads(db.execute("SELECT json_serialize_sql(?,skip_default:=true,skip_empty:=true,skip_null:=true)", [query]).fetchone()[0])
            for j, prefix in enumerate([bytes([107, 0, 0, 0]), bytes([255, 1, 1, 1]), bytes(4)]):
                (corpus / f"seed-{i}-{j}").write_bytes(prefix + json.dumps({"ast": ast}).encode())
            node = ast.get("statements", [{}])[0].get("node", {})
            if node.get("type") == "SET_OPERATION_NODE" and "left" in node:
                node["children"] = [node.pop("left"), node.pop("right")]
                (corpus / f"children-{i}").write_bytes(bytes([107, 0, 0, 0]) + json.dumps({"ast": ast}).encode())
    command = [os.environ.get("CXX", "clang++"), "-std=c++17", "-O1", "-g", "-fsanitize=fuzzer,address,undefined", "-fno-sanitize=vptr", "-fno-omit-frame-pointer"]
    for path in ["src/include", "duckdb/src/include", "duckdb/third_party/yyjson/include"]:
        command += ["-I" + str(root / path)]
    command += ["-I" + str(generated)]
    command += [str(root / "test/fuzz/validator_fuzz.cpp"), str(root / "src/validator.cpp"),
                str(root / "duckdb/third_party/yyjson/yyjson.cpp"),
                "-o", str(out / "validator_fuzz")]
    subprocess.run(command, check=True)
    # Everything in this binary is instrumented, so container-overflow detection stays on.
    run_libfuzzer(out / "validator_fuzz", corpus, out / "run.log", args.seconds, max_len=65536,
                  env=environment(mixed_runtime=False))


if __name__ == "__main__":
    main()
