"""Coverage-guided native JSON policy/AST fuzzing using clang libFuzzer and ASan/UBSan."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=60)
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    root = Path(__file__).resolve().parents[1]
    subprocess.run([sys.executable, str(root / "scripts/generate.py")], check=True)
    out = root / "build/fuzz"
    out.mkdir(parents=True, exist_ok=True)
    corpus = out / "corpus"
    corpus.mkdir(exist_ok=True)
    import duckdb
    with duckdb.connect() as db:
        for i, query in enumerate(["SELECT 1", "SELECT md5('x')", "SELECT * FROM private.t",
                                   "WITH t AS (SELECT 1) SELECT * FROM t", "SELECT * FROM range(3)",
                                   "WITH RECURSIVE t AS (SELECT 1 n UNION ALL SELECT n+1 FROM t WHERE n<3) SELECT * FROM t",
                                   "SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT md5('x')",
                                   "SELECT NULL::STRUCT(x INTEGER, y INET[])", "SELECT [1,2][1]",
                                   "SELECT current_schema", "SELECT 'x' COLLATE de"]):
            ast = json.loads(db.execute("SELECT json_serialize_sql(?,skip_default:=true,skip_empty:=true,skip_null:=true)", [query]).fetchone()[0])
            for j, prefix in enumerate([bytes([107, 30, 0, 0, 0, 0]), bytes([255, 63, 1, 1, 1, 1]), bytes(6)]):
                (corpus / f"seed-{i}-{j}").write_bytes(prefix + json.dumps({"ast": ast}).encode())
            node = ast.get("statements", [{}])[0].get("node", {})
            if node.get("type") == "SET_OPERATION_NODE" and "left" in node:
                node["children"] = [node.pop("left"), node.pop("right")]
                (corpus / f"children-{i}").write_bytes(bytes([107, 30, 0, 0, 0, 0]) + json.dumps({"ast": ast}).encode())
    command = [os.environ.get("CXX", "clang++"), "-std=c++17", "-O1", "-g", "-fsanitize=fuzzer,address,undefined", "-fno-sanitize=vptr", "-fno-omit-frame-pointer"]
    for path in ["src/include", "generated", "duckdb/src/include", "duckdb/third_party/yyjson/include"]:
        command += ["-I" + str(root / path)]
    command += [str(root / "test/fuzz/validator_fuzz.cpp"), str(root / "src/validator.cpp"),
                str(root / "duckdb/third_party/yyjson/yyjson.cpp"),
                "-o", str(out / "validator_fuzz")]
    subprocess.run(command, check=True)
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    env["UBSAN_OPTIONS"] = "halt_on_error=1"
    with (out / "run.log").open("w") as log:
        result = subprocess.run([str(out / "validator_fuzz"), str(corpus), "-max_total_time=" + str(args.seconds),
                                 "-max_len=65536", "-timeout=5", "-artifact_prefix=" + str(out) + "/"],
                                env=env, stdout=log, stderr=log)
    lines = (out / "run.log").read_text(errors="replace").splitlines()
    for line in lines:
        if "DONE" in line or line.startswith("Done ") or "ERROR:" in line or "SUMMARY:" in line:
            print(line)
    print("Full log:", out / "run.log")
    result.check_returncode()


if __name__ == "__main__":
    main()
