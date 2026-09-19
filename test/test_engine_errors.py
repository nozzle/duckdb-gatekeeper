import subprocess

from support.artifact import ROOT
from support.toolchain import compile_cpp


def test_engine_error_classification(tmp_path):
    binary = compile_cpp([ROOT / "test/engine_errors.cpp"], tmp_path / "engine_errors",
                         includes=[ROOT / "src/include", ROOT / "duckdb/src/include"])
    subprocess.run([str(binary)], check=True)
