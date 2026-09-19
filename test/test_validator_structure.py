import copy
import json
import subprocess
import sys

import pytest

from support.artifact import ROOT
from support.toolchain import compile_cpp


@pytest.fixture(scope="module")
def native_validator(tmp_path_factory):
    work = tmp_path_factory.mktemp("validator")
    generated = work / "generated"
    subprocess.run([sys.executable, str(ROOT / "scripts/generate.py"), "--output", str(generated)], check=True)
    binary = compile_cpp([ROOT / "test/validator_structure.cpp", ROOT / "src/validator.cpp",
                          ROOT / "duckdb/third_party/yyjson/yyjson.cpp"], work / "validator", flags=["-O1"],
                         includes=[generated, ROOT / "src/include", ROOT / "duckdb/src/include",
                                   ROOT / "duckdb/third_party/yyjson/include"])

    def run(ast):
        return subprocess.check_output([str(binary)], input=json.dumps(ast).encode()).decode()

    def code(ast):
        return run(ast).splitlines()[0]

    # (rule, function_name, position) per violation, in the walker's order; position -1 means none.
    code.violations = lambda ast: [tuple(line.split("\t")) for line in run(ast).splitlines()[1:]]
    return code


def test_set_operation_representations_and_all_branches(db, native_validator):
    def ast(sql):
        return json.loads(db.execute("SELECT json_serialize_sql(?, skip_default:=true, skip_empty:=true, skip_null:=true)",
                                     [sql]).fetchone()[0])
    pair = ast("SELECT 1 UNION ALL SELECT 2")
    assert native_validator(pair) == "ok"
    latest = copy.deepcopy(pair)
    node = latest["statements"][0]["node"]
    node["children"] = [node.pop("left"), node.pop("right")]
    assert native_validator(latest) == "ok"
    node["children"].append(ast("SELECT md5('x')")["statements"][0]["node"])
    assert native_validator(latest) == "forbidden"
    for children in [[], [node["children"][0]], None, "invalid"]:
        malformed = copy.deepcopy(latest)
        malformed["statements"][0]["node"]["children"] = children
        assert native_validator(malformed) == "unsupported"
    for field in ["left", "right"]:
        malformed = copy.deepcopy(pair)
        del malformed["statements"][0]["node"][field]
        assert native_validator(malformed) == "unsupported"
    node["left"] = node["children"][0]
    assert native_validator(latest) == "unsupported"


def test_serialized_bind_time_sites(db, native_validator):
    # Exercise serializer-only shapes independently of SQL parser restrictions.
    ast = json.loads(db.execute("SELECT json_serialize_sql('SELECT 1', skip_default:=true, skip_empty:=true, skip_null:=true)").fetchone()[0])
    computation = json.loads(db.execute("SELECT json_serialize_sql('SELECT abs(1)', skip_default:=true, skip_empty:=true, skip_null:=true)").fetchone()[0])["statements"][0]["node"]["select_list"][0]
    for modifier in ["LIMIT_MODIFIER", "LIMIT_PERCENT_MODIFIER"]:
        candidate = copy.deepcopy(ast)
        candidate["statements"][0]["node"]["modifiers"] = [{"type": modifier, "limit": computation}]
        assert native_validator(candidate) == "forbidden"
    candidate = copy.deepcopy(ast)
    candidate["statements"][0]["node"]["select_list"] = [{
        "class": "CAST", "type": "OPERATOR_CAST", "child": ast["statements"][0]["node"]["select_list"][0],
        "cast_type": {"id": "UNBOUND", "type_info": {"expr": {
            "class": "TYPE", "type": "TYPE", "type_name": "decimal", "children": [computation]}}}}]
    assert native_validator(candidate) == "forbidden"


def test_serialized_type_collation_is_host_trusted(db, native_validator):
    ast = json.loads(db.execute("SELECT json_serialize_sql('SELECT 1', skip_default:=true, skip_empty:=true, skip_null:=true)").fetchone()[0])
    literal = json.loads(db.execute("SELECT json_serialize_sql(?, skip_default:=true, skip_empty:=true, skip_null:=true)",
                                   ["SELECT 'de'"]).fetchone()[0])["statements"][0]["node"]["select_list"][0]
    literal["alias"] = "collation"
    ast["statements"][0]["node"]["select_list"] = [{
        "class": "CAST", "type": "OPERATOR_CAST", "child": literal,
        "cast_type": {"id": "UNBOUND", "type_info": {"expr": {
            "class": "TYPE", "type": "TYPE", "type_name": "varchar", "children": [literal]}}}}]
    assert native_validator(ast) == "ok"


def expression(db, sql):
    return json.loads(db.execute("SELECT json_serialize_sql(?, skip_default:=true, skip_empty:=true, skip_null:=true)",
                                 [sql]).fetchone()[0])["statements"][0]["node"]["select_list"][0]


@pytest.mark.parametrize("order", ["explicit first", "implied first", "implied twice"])
def test_function_position_is_the_earliest_location_however_the_name_was_reached(db, native_validator, order):
    """One rule for a denied function's position: the smallest query_location among every occurrence, whether
    the name was written (list_value(1)) or implied by syntax (ARRAY[1] is list_value too).

    The pinned engine's serializer stamps no query_location on operator nodes, so through SQL the implied
    occurrence never has a position and the rule cannot be told from "first occurrence encountered". These ASTs
    give the operator node one, as another serializer version may.
    """
    ast = json.loads(db.execute("SELECT json_serialize_sql('SELECT 1', skip_default:=true, skip_empty:=true, skip_null:=true)").fetchone()[0])
    written = expression(db, "SELECT list_value(1)")
    written["query_location"] = 10
    implied = expression(db, "SELECT ARRAY[1]")
    assert implied["class"] == "OPERATOR" and "query_location" not in implied
    implied["query_location"] = 3
    later = copy.deepcopy(implied)
    later["query_location"] = 7
    select_list = {"explicit first": [written, implied], "implied first": [implied, written],
                   "implied twice": [implied, later]}[order]
    ast["statements"][0]["node"]["select_list"] = select_list
    assert native_validator.violations(ast) == [("function", "list_value", "3")]
