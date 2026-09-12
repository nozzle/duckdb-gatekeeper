import os
import subprocess

from test_gatekeeper import ROOT


def test_engine_error_classification(tmp_path):
    binary = tmp_path / "engine_errors"
    subprocess.run([os.environ.get("CXX", "c++"), "-std=c++17", "-I" + str(ROOT / "src/include"),
                    "-I" + str(ROOT / "duckdb/src/include"), str(ROOT / "test/engine_errors.cpp"),
                    "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
