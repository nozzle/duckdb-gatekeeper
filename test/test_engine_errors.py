import subprocess

from support.artifact import ROOT
from support.toolchain import compile_cpp


def test_engine_error_classification(tmp_path):
    # engine_errors.hpp names the result codes validator.hpp defines, and validator.hpp names yyjson's types.
    binary = compile_cpp([ROOT / "test/engine_errors.cpp"], tmp_path / "engine_errors",
                         includes=[ROOT / "src/include", ROOT / "duckdb/src/include",
                                   ROOT / "duckdb/third_party/yyjson/include"])
    subprocess.run([str(binary)], check=True)
