import copy
import json
import os
import subprocess

import pytest

from test_gatekeeper import ROOT, db


@pytest.fixture(scope="module")
def native_validator(tmp_path_factory):
    binary = tmp_path_factory.mktemp("validator") / "validator"
    command = [os.environ.get("CXX", "c++"), "-std=c++17", "-O1"]
    for path in ["src/include", "generated", "duckdb/src/include", "duckdb/third_party/yyjson/include"]:
        command.append("-I" + str(ROOT / path))
    command += [str(ROOT / path) for path in ["test/validator_structure.cpp", "src/validator.cpp",
                                             "duckdb/third_party/yyjson/yyjson.cpp"]]
    subprocess.run(command + ["-o", str(binary)], check=True)
    return lambda ast: subprocess.check_output([str(binary)], input=json.dumps(ast).encode()).decode()


def test_set_operation_representations_and_all_branches(db, native_validator):
    def ast(sql):
        return json.loads(db.execute("SELECT json_serialize_sql(?, skip_default:=true, skip_empty:=true, skip_null:=true)",
                                     [sql]).fetchone()[0])
    legacy = ast("SELECT 1 UNION ALL SELECT 2")
    assert native_validator(legacy) == "ok"
    modern = copy.deepcopy(legacy)
    node = modern["statements"][0]["node"]
    node["children"] = [node.pop("left"), node.pop("right")]
    assert native_validator(modern) == "ok"
    node["children"].append(ast("SELECT md5('x')")["statements"][0]["node"])
    assert native_validator(modern) == "forbidden"
    for children in [[], [node["children"][0]], None, "invalid"]:
        malformed = copy.deepcopy(modern)
        malformed["statements"][0]["node"]["children"] = children
        assert native_validator(malformed) == "unsupported"
    for field in ["left", "right"]:
        malformed = copy.deepcopy(legacy)
        del malformed["statements"][0]["node"][field]
        assert native_validator(malformed) == "unsupported"
    node["left"] = node["children"][0]
    assert native_validator(modern) == "unsupported"
