"""Generate immutable C++ data from the pinned serializer and reviewed inventory."""
import json
from pathlib import Path
import subprocess
from inventory import load

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "duckdb/src/include/duckdb/storage/serialization"


def grammar():
    primitives = {
        "string": "string", "bool": "boolean", "optional_idx": "number",
        "idx_t": "number", "int64_t": "number", "Value": "opaque",
        "LogicalType": "opaque", "GroupingSet": "opaque",
        "case_insensitive_set_t": "opaque", "qualified_column_set_t": "opaque",
        "qualified_column_map_t<string>": "opaque", "case_insensitive_map_t<idx_t>": "opaque",
        "case_insensitive_map_t<ParsedExpression*>": "replacement[]",
        "InsertionOrderPreservingMap<CommonTableExpressionInfo*>": "cte_entry[]",
    }
    enums = set("QueryNodeType AggregateHandling SetOperationType CTEMaterialize TableReferenceType JoinType JoinRefType OrdinalityType ShowType ResultModifierType OrderType OrderByNullType SampleMethod ExpressionClass ExpressionType LambdaSyntaxType SubqueryType WindowBoundary WindowExcludeMode".split())
    allowed = set("SelectStatement QueryNode SelectNode SetOperationNode RecursiveCTENode TableRef BaseTableRef JoinRef SubqueryRef TableFunctionRef EmptyTableRef ExpressionListRef PivotRef ShowRef AtClause ParsedExpression BetweenExpression CaseExpression CastExpression CollateExpression ColumnRefExpression ComparisonExpression ConjunctionExpression ConstantExpression FunctionExpression LambdaExpression OperatorExpression ParameterExpression PositionalReferenceExpression StarExpression SubqueryExpression WindowExpression CommonTableExpressionInfo CommonTableExpressionMap OrderByNode CaseCheck SampleOptions PivotColumn PivotColumnEntry ResultModifier LimitModifier DistinctModifier OrderModifier LimitPercentModifier".split())
    entries = {}
    for name in ["statement", "query_node", "tableref", "parsed_expression", "result_modifier", "nodes"]:
        for entry in json.loads((SOURCE / (name + ".json")).read_text()):
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
        "SetOperationNode": ["type", "setop_type", "left", "right"],
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


def main():
    revision = subprocess.check_output(["git", "-C", str(ROOT / "duckdb"), "rev-parse", "HEAD"], text=True).strip()
    if revision != "d8cdaa33fda8df955cc76ef58a280f68f4cd43fa":
        raise ValueError("Gatekeeper phase 1 requires the pinned DuckDB 1.5.5 revision")
    _, defaults = load()
    inventory = {"defaults": defaults}
    generated = ROOT / "generated"
    generated.mkdir(exist_ok=True)
    for name, data in [("grammar", grammar()), ("inventory", inventory)]:
        text = json.dumps(data, separators=(",", ":"), ensure_ascii=True)
        (generated / (name + ".hpp")).write_text(
            'static const char *' + name + '_json = R"DATA(' + text + ')DATA";\n'
        )


if __name__ == "__main__":
    main()
