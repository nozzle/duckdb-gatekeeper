"""Generate immutable C++ data from the build engine's serializer and function inventory."""
import sys

if sys.version_info < (3, 10):
    raise SystemExit("Gatekeeper generation requires Python 3.10 or newer")

import argparse
import json
from pathlib import Path
import re
from inventory import load
from versions import EXTENSION_VERSION, SUPPORTED_DUCKDB, SUPPORTED_DUCKDB_REVISION

ROOT = Path(__file__).resolve().parents[1]
STAMP_WIDTH = 96


def grammar(duckdb_source=ROOT / "duckdb"):
    source = duckdb_source / "src/include/duckdb/storage/serialization"
    primitives = {
        "string": "string", "bool": "boolean", "optional_idx": "number",
        "idx_t": "number", "int64_t": "number", "Value": "opaque",
        "LogicalType": "logical_type", "GroupingSet": "opaque",
        "case_insensitive_set_t": "opaque", "qualified_column_set_t": "opaque",
        "qualified_column_map_t<string>": "opaque", "case_insensitive_map_t<idx_t>": "opaque",
        "case_insensitive_map_t<ParsedExpression*>": "replacement[]",
        "InsertionOrderPreservingMap<CommonTableExpressionInfo*>": "cte_entry[]",
    }
    enums = set("QueryNodeType AggregateHandling SetOperationType CTEMaterialize TableReferenceType JoinType JoinRefType OrdinalityType ShowType ResultModifierType OrderType OrderByNullType SampleMethod ExpressionClass ExpressionType LambdaSyntaxType SubqueryType WindowBoundary WindowExcludeMode".split())
    allowed = set("SelectStatement QueryNode SelectNode SetOperationNode RecursiveCTENode TableRef BaseTableRef JoinRef SubqueryRef TableFunctionRef EmptyTableRef ExpressionListRef PivotRef ShowRef AtClause ParsedExpression BetweenExpression CaseExpression CastExpression CollateExpression ColumnRefExpression ComparisonExpression ConjunctionExpression ConstantExpression FunctionExpression LambdaExpression OperatorExpression ParameterExpression PositionalReferenceExpression StarExpression SubqueryExpression WindowExpression TypeExpression CommonTableExpressionInfo CommonTableExpressionMap OrderByNode CaseCheck SampleOptions PivotColumn PivotColumnEntry ResultModifier LimitModifier DistinctModifier OrderModifier LimitPercentModifier".split())
    entries = {}
    for name in ["statement", "query_node", "tableref", "parsed_expression", "result_modifier", "nodes"]:
        for entry in json.loads((source / (name + ".json")).read_text()):
            if entry["class"] in allowed:
                entries[entry["class"]] = entry

    def resolve(typ):
        if typ in primitives:
            return primitives[typ]
        if typ in enums:
            return "string"
        if typ.endswith("*"):
            return resolve(typ[:-1])
        if typ.startswith("unique_ptr<"):
            return resolve(typ[11:-1])
        if typ.startswith("vector<"):
            return resolve(typ[7:-1]) + "[]"
        if typ in allowed:
            return typ
        raise ValueError("Unreviewed field type: " + typ)

    required = {
        "SelectStatement": ["node"], "SelectNode": ["type", "select_list", "from_table"],
        "SetOperationNode": ["type", "setop_type"],
        "RecursiveCTENode": ["type", "cte_name", "left", "right"],
        "CommonTableExpressionInfo": ["query"], "BaseTableRef": ["type", "table_name"],
        "JoinRef": ["type", "left", "right"], "SubqueryRef": ["type", "subquery"],
        "TableFunctionRef": ["type", "function"], "EmptyTableRef": ["type"],
        "ExpressionListRef": ["type", "values"], "PivotRef": ["type", "source"],
        "ShowRef": ["type", "show_type"], "AtClause": ["unit", "expr"],
        "OrderByNode": ["expression"], "CaseCheck": ["when_expr", "then_expr"],
        "SampleOptions": ["sample_size"], "ConstantExpression": ["value"],
        "FunctionExpression": ["function_name"], "WindowExpression": ["function_name"],
        "SubqueryExpression": ["subquery", "subquery_type"],
        "BetweenExpression": ["input", "lower", "upper"], "CaseExpression": ["else_expr"],
        "CastExpression": ["child", "cast_type"], "CollateExpression": ["child", "collation"],
        "ColumnRefExpression": ["column_names"], "ComparisonExpression": ["left", "right"],
        "ConjunctionExpression": ["children"], "LambdaExpression": ["lhs", "expr"],
        "OperatorExpression": ["children"], "ParameterExpression": ["identifier"],
        "PositionalReferenceExpression": ["index"],
        "TypeExpression": ["type_name"],
    }
    rules, dispatch = {}, {}
    for name, entry in entries.items():
        members = entries[entry["base"]]["members"] if "base" in entry else []
        members = members + entry["members"]
        fields = {m["name"]: resolve(m["type"]) for m in members if m.get("status") != "deleted"}
        rule = {"fields": fields, "required": required.get(name, []).copy()}
        if entry.get("base") == "ParsedExpression":
            rule["required"] += ["class", "type"]
        rules[name] = rule
        if "base" in entry:
            tag = "EMPTY" if entry["enum"] == "EMPTY_FROM" else entry["enum"]
            dispatch.setdefault(entry["base"], {})[tag] = name
    rules["root"] = {"fields": {"error": "boolean", "statements": "SelectStatement[]"}, "required": ["error", "statements"]}
    rules["cte_entry"] = {"fields": {"key": "string", "value": "CommonTableExpressionInfo"}, "required": ["key", "value"]}
    rules["replacement"] = {"fields": {"key": "string", "value": "ParsedExpression"}, "required": ["key", "value"]}
    return {"rules": rules, "dispatch": dispatch}


def header(name, data):
    text = json.dumps(data, separators=(",", ":"), ensure_ascii=True)
    # Separate raw literals avoid MSVC C2026; splitting inside JSON escapes is safe.
    if ')DATA"' in text:
        raise ValueError("generated JSON collides with raw string delimiter")
    chunks = [text[i:i + 8000] for i in range(0, len(text), 8000)]
    return 'static const char *' + name + '_json =\n' + '\n'.join('R"DATA(' + chunk + ')DATA"' for chunk in chunks) + ';\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "generated",
                        help="directory for generated headers (the build passes its binary dir)")
    parser.add_argument("--duckdb-source", type=Path, default=ROOT / "duckdb",
                        help="DuckDB source being compiled; defaults to the local submodule")
    parser.add_argument("--duckdb-version", default="v" + SUPPORTED_DUCKDB,
                        help="engine version tag DuckDB stamps into the build (CMake DUCKDB_VERSION)")
    parser.add_argument("--duckdb-source-id", default=SUPPORTED_DUCKDB_REVISION[:10],
                        help="engine source id DuckDB stamps into the build (CMake GIT_COMMIT_HASH)")
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+)?", args.duckdb_version):
        raise SystemExit("Refusing to bake an unrecognised engine version into the guard: " + args.duckdb_version)
    if not re.fullmatch(r"[0-9a-f]{7,40}", args.duckdb_source_id):
        raise SystemExit("Refusing to bake an engine source id that is not a 7-40 hex commit id: "
                         + repr(args.duckdb_source_id))
    _, defaults = load()
    inventory = {"defaults": defaults}
    build_grammar = grammar(args.duckdb_source)
    args.output.mkdir(parents=True, exist_ok=True)
    for name, data in [("grammar", build_grammar), ("inventory", inventory)]:
        target = args.output / (name + ".hpp")
        content = header(name, data)
        # Leave the timestamp alone when nothing changed so reconfiguring does not force a rebuild.
        if not target.exists() or target.read_text() != content:
            target.write_text(content)
    target = args.output / "version.hpp"
    # The engine guard in LoadInternal parses this stamp at load time and compares it with the host. It is one
    # string so `strings gatekeeper.duckdb_extension | grep GATEKEEPER_BUILD_ENGINE` shows which engine an
    # artifact was built for, and so tests can rewrite it in place to prove the guard refuses a mismatch.
    # The array is fixed-width and NUL padded so a rewritten stamp of a different length still fits in place.
    stamp = f"GATEKEEPER_BUILD_ENGINE {args.duckdb_version} {args.duckdb_source_id}"
    if len(stamp) >= STAMP_WIDTH:
        raise SystemExit("Build engine stamp is too long: " + stamp)
    content = ('#pragma once\nnamespace gatekeeper {\n'
               f'constexpr const char *VERSION = "{EXTENSION_VERSION}";\n'
               f'constexpr char BUILD_ENGINE_STAMP[{STAMP_WIDTH}] = "{stamp}";\n'
               '} // namespace gatekeeper\n')
    if not target.exists() or target.read_text() != content:
        target.write_text(content)


if __name__ == "__main__":
    main()
