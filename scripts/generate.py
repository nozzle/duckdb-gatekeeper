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
        # DuckDB 2.0. An Identifier is written exactly like a plain string (Serializer::WriteValue(const
        # Identifier &)), so every identifier-keyed container keeps the shape of its string-keyed predecessor.
        "Identifier": "string", "duckdb::Identifier": "string", "uint32_t": "number", "double": "number",
        "identifier_set_t": "opaque", "identifier_map_t<idx_t>": "opaque",
        "qualified_column_map_t<Identifier>": "opaque",
        "identifier_map_t<ParsedExpression*>": "replacement[]",
        "InsertionOrderPreservingMap<CommonTableExpressionInfo*, Identifier, identifier_map_t<idx_t>>": "cte_entry[]",
        # Structured 2.0 values with rules of their own below. A literal is the token text with no expression
        # inside; a qualified name is a path of identifiers; a function argument wraps an expression the walk
        # must reach.
        "Literal": "literal", "QualifiedName": "qualified_name", "FunctionArgument": "function_argument",
    }
    enums = set("QueryNodeType AggregateHandling SetOperationType CTEMaterialize TableReferenceType JoinType JoinRefType OrdinalityType ShowType ResultModifierType OrderType OrderByNullType SampleMethod ExpressionClass ExpressionType LambdaSyntaxType SubqueryType WindowBoundary WindowExcludeMode LimitValueType".split())
    allowed = set("SelectStatement QueryNode SelectNode SetOperationNode RecursiveCTENode TableRef BaseTableRef JoinRef SubqueryRef TableFunctionRef EmptyTableRef ExpressionListRef PivotRef ShowRef AtClause ParsedExpression BetweenExpression CaseExpression CastExpression CollateExpression ColumnRefExpression ComparisonExpression ConjunctionExpression ConstantExpression FunctionExpression LambdaExpression OperatorExpression ParameterExpression PositionalReferenceExpression StarExpression SubqueryExpression WindowExpression TypeExpression CommonTableExpressionInfo CommonTableExpressionMap OrderByNode CaseCheck SampleOptions PivotColumn PivotColumnEntry ResultModifier LimitModifier DistinctModifier OrderModifier LimitPercentModifier LegacyLimitPercentModifier".split())
    # Classes DuckDB 2.0 serializes by hand (custom_implementation). Their schema entries describe the C++
    # members, not the properties written, so the properties come from the implementation instead
    # (src/parser/expression/{cast,function,window}_expression.cpp at the latest storage version, which is what
    # Gatekeeper serializes with). Reviewed against the same engine as the schema files; a hand-serialized class
    # without an entry here is refused rather than guessed.
    latest = {
        "CastExpression": {"child": "ParsedExpression*", "try_cast": "bool", "type_expr": "ParsedExpression*"},
        "FunctionExpression": {
            "function_name": "Identifier", "schema": "Identifier", "filter": "ParsedExpression*",
            "order_bys": "OrderModifier*", "distinct": "bool", "is_operator": "bool", "export_state": "bool",
            "catalog": "Identifier", "arguments": "vector<FunctionArgument>", "qualified_name": "QualifiedName",
        },
        "WindowExpression": {
            "function_name": "Identifier", "schema": "Identifier", "catalog": "Identifier",
            "partitions": "vector<ParsedExpression*>", "orders": "vector<OrderByNode>",
            "start": "WindowBoundary", "end": "WindowBoundary", "start_expr": "ParsedExpression*",
            "end_expr": "ParsedExpression*", "offset_expr": "ParsedExpression*", "default_expr": "ParsedExpression*",
            "ignore_nulls": "bool", "filter_expr": "ParsedExpression*", "exclude_clause": "WindowExcludeMode",
            "distinct": "bool", "arg_orders": "vector<OrderByNode>", "has_ignore_nulls": "bool",
            "arguments": "vector<FunctionArgument>", "qualified_name": "QualifiedName",
        },
    }
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
    # DuckDB 2.0 moves each of these into a new property and stops writing the old one at the latest storage
    # version; the requirement follows the property the engine being built actually writes.
    successors = {"value": "literal", "cast_type": "type_expr", "query": "query_node"}
    rules, dispatch = {}, {}
    for name, entry in entries.items():
        members = entries[entry["base"]]["members"] if "base" in entry else []
        if entry.get("custom_implementation"):
            if name not in latest:
                raise ValueError("Unreviewed hand-serialized class: " + name)
            members = members + [{"name": field, "type": typ} for field, typ in latest[name].items()]
        else:
            members = members + entry["members"]
        fields = {m["name"]: resolve(m["type"]) for m in members if m.get("status") != "deleted"}
        rule = {"fields": fields, "required": [successors.get(f) if successors.get(f) in fields else f
                                               for f in required.get(name, [])]}
        if entry.get("base") == "ParsedExpression":
            rule["required"] += ["class", "type"]
        rules[name] = rule
        if "base" in entry:
            tag = "EMPTY" if entry["enum"] == "EMPTY_FROM" else entry["enum"]
            dispatch.setdefault(entry["base"], {})[tag] = name
    rules["root"] = {"fields": {"error": "boolean", "statements": "SelectStatement[]"}, "required": ["error", "statements"]}
    rules["cte_entry"] = {"fields": {"key": "string", "value": "CommonTableExpressionInfo"}, "required": ["key", "value"]}
    rules["replacement"] = {"fields": {"key": "string", "value": "ParsedExpression"}, "required": ["key", "value"]}
    # DuckDB 2.0 (Literal::Serialize, QualifiedName::Serialize, FunctionArgument::Serialize). Only the argument
    # holds an expression; empty names, paths and texts are omitted as defaults.
    rules["literal"] = {"fields": {"kind": "string", "text": "string"}, "required": ["kind"]}
    rules["qualified_name"] = {"fields": {"path": "string[]"}, "required": []}
    rules["function_argument"] = {"fields": {"name": "string", "expression": "ParsedExpression"}, "required": ["expression"]}
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
    # The identity CMake has already computed for the engine it is compiling, to be baked into the load-time
    # guard as-is. (The build scripts' --duckdb-version, in engine.py, is different: it tells the engine build
    # how to compute that identity.)
    parser.add_argument("--engine-version-label", default="v" + SUPPORTED_DUCKDB,
                        help="engine version tag DuckDB stamps into the build (CMake DUCKDB_VERSION)")
    parser.add_argument("--engine-source-id", default=SUPPORTED_DUCKDB_REVISION[:10],
                        help="engine source id DuckDB stamps into the build (CMake GIT_COMMIT_HASH)")
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+)?", args.engine_version_label):
        raise SystemExit("Refusing to bake an unrecognised engine version into the guard: " + args.engine_version_label)
    if not re.fullmatch(r"[0-9a-f]{7,40}", args.engine_source_id):
        raise SystemExit("Refusing to bake an engine source id that is not a 7-40 hex commit id: "
                         + repr(args.engine_source_id))
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
    stamp = f"GATEKEEPER_BUILD_ENGINE {args.engine_version_label} {args.engine_source_id}"
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
