import copy
import json
import subprocess
import sys

import pytest

from support.artifact import ENGINE_MAJOR, ENGINE_SOURCE, ROOT, by_engine
from support.toolchain import compile_cpp


def test_schema_path_identity_and_attribution(tmp_path):
    generated = tmp_path / "generated"
    subprocess.run([sys.executable, str(ROOT / "scripts/generate.py"), "--output", str(generated),
                    "--duckdb-source", str(ENGINE_SOURCE)], check=True)
    binary = compile_cpp([ROOT / "test/schema_path_identity.cpp", ROOT / "src/validator.cpp",
                          ENGINE_SOURCE / "third_party/yyjson/yyjson.cpp"], tmp_path / "paths", flags=["-O1"],
                         includes=[generated, ROOT / "src/include", ENGINE_SOURCE / "src/include",
                                   ENGINE_SOURCE / "third_party/yyjson/include"])
    subprocess.run([str(binary)], check=True)


@pytest.fixture(scope="module")
def native_validator(tmp_path_factory):
    work = tmp_path_factory.mktemp("validator")
    generated = work / "generated"
    subprocess.run([sys.executable, str(ROOT / "scripts/generate.py"), "--output", str(generated),
                    "--duckdb-source", str(ENGINE_SOURCE)], check=True)
    binary = compile_cpp([ROOT / "test/validator_structure.cpp", ROOT / "src/validator.cpp",
                          ENGINE_SOURCE / "third_party/yyjson/yyjson.cpp"], work / "validator", flags=["-O1"],
                         includes=[generated, ROOT / "src/include", ENGINE_SOURCE / "src/include",
                                   ENGINE_SOURCE / "third_party/yyjson/include"])

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
    # DuckDB 1.5's json_serialize_sql writes a set operation as a left/right pair and the latest storage version
    # (Gatekeeper's own serialization, 2.0's json_serialize_sql) as a children list; both shapes are validated.
    serialized = ast("SELECT 1 UNION ALL SELECT 2")
    if "children" in serialized["statements"][0]["node"]:
        latest, pair = serialized, copy.deepcopy(serialized)
        node = pair["statements"][0]["node"]
        node["left"], node["right"] = node.pop("children")
    else:
        pair, latest = serialized, copy.deepcopy(serialized)
        node = latest["statements"][0]["node"]
        node["children"] = [node.pop("left"), node.pop("right")]
    assert native_validator(pair) == "ok"
    node = latest["statements"][0]["node"]
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


def cast(child, type_name, parameters):
    """A CAST node as the engine under test serializes one: DuckDB 1.5 writes the target as a bound LogicalType
    whose unbound form carries the type expression, 2.0 writes the type expression itself."""
    target = {"class": "TYPE", "type": "TYPE", "type_name": type_name, "children": parameters}
    node = {"class": "CAST", "type": "OPERATOR_CAST", "child": child}
    if ENGINE_MAJOR >= 2:
        node["type_expr"] = target
    else:
        node["cast_type"] = {"id": "UNBOUND", "type_info": {"expr": target}}
    return node


def test_serialized_bind_time_sites(db, native_validator):
    # Exercise serializer-only shapes independently of SQL parser restrictions.
    ast = json.loads(db.execute("SELECT json_serialize_sql('SELECT 1', skip_default:=true, skip_empty:=true, skip_null:=true)").fetchone()[0])
    computation = json.loads(db.execute("SELECT json_serialize_sql('SELECT abs(1)', skip_default:=true, skip_empty:=true, skip_null:=true)").fetchone()[0])["statements"][0]["node"]["select_list"][0]
    for modifier in ["LIMIT_MODIFIER", by_engine(v1="LIMIT_PERCENT_MODIFIER", v2="LEGACY_LIMIT_PERCENT_MODIFIER")]:
        candidate = copy.deepcopy(ast)
        candidate["statements"][0]["node"]["modifiers"] = [{"type": modifier, "limit": computation}]
        assert native_validator(candidate) == "forbidden"
    candidate = copy.deepcopy(ast)
    candidate["statements"][0]["node"]["select_list"] = [
        cast(ast["statements"][0]["node"]["select_list"][0], "decimal", [computation])]
    assert native_validator(candidate) == "forbidden"


def test_serialized_type_collation_is_host_trusted(db, native_validator):
    ast = json.loads(db.execute("SELECT json_serialize_sql('SELECT 1', skip_default:=true, skip_empty:=true, skip_null:=true)").fetchone()[0])
    literal = json.loads(db.execute("SELECT json_serialize_sql(?, skip_default:=true, skip_empty:=true, skip_null:=true)",
                                   ["SELECT 'de'"]).fetchone()[0])["statements"][0]["node"]["select_list"][0]
    literal["alias"] = "collation"
    ast["statements"][0]["node"]["select_list"] = [cast(literal, "varchar", [literal])]
    assert native_validator(ast) == "ok"


def expression(db, sql):
    return json.loads(db.execute("SELECT json_serialize_sql(?, skip_default:=true, skip_empty:=true, skip_null:=true)",
                                  [sql]).fetchone()[0])["statements"][0]["node"]["select_list"][0]


@pytest.mark.skipif(ENGINE_MAJOR < 2, reason="qualified_name serialization requires DuckDB 2.0")
def test_empty_written_path_is_unsupported(db, native_validator):
    ast = json.loads(db.execute("SELECT json_serialize_sql('SELECT * FROM main.t')").fetchone()[0])
    ast["statements"][0]["node"]["from_table"]["qualified_name"]["path"] = []
    assert native_validator(ast) == "unsupported"


@pytest.mark.parametrize("order", ["explicit first", "implied first", "implied twice"])
def test_function_position_is_the_earliest_location_however_the_name_was_reached(db, native_validator, order):
    """One rule for a denied function's position: the smallest query_location among every occurrence, whether
    the name was written (list_value(1)) or implied by syntax (ARRAY[1] is list_value too).

    DuckDB 1.5's default parser stamps no query_location on operator nodes, so through SQL the implied
    occurrence never has a position and the rule cannot be told from "first occurrence encountered". These ASTs
    give the operator node one, as the PEG parser (2.0's only parser) does.
    """
    ast = json.loads(db.execute("SELECT json_serialize_sql('SELECT 1', skip_default:=true, skip_empty:=true, skip_null:=true)").fetchone()[0])
    written = expression(db, "SELECT list_value(1)")
    written["query_location"] = 10
    implied = expression(db, "SELECT ARRAY[1]")
    assert implied["class"] == "OPERATOR"
    implied["query_location"] = 3
    later = copy.deepcopy(implied)
    later["query_location"] = 7
    select_list = {"explicit first": [written, implied], "implied first": [implied, written],
                   "implied twice": [implied, later]}[order]
    ast["statements"][0]["node"]["select_list"] = select_list
    assert native_validator.violations(ast) == [("function", "list_value", "3")]
