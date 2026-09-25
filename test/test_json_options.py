"""JSON is an input encoding of the typed API, with a published authoring schema."""
import json

import duckdb
from jsonschema import Draft202012Validator
import pytest

from support.artifact import ROOT
from support.audit import decisions, enable, records
from support.typed_helpers import configure, policy, validate


SCHEMA = json.loads((ROOT / "docs/policy-v2.schema.json").read_text())
SCHEMA_VALIDATOR = Draft202012Validator(SCHEMA)


def document(options):
    return {"version": 2, "options": options}


def encoded(options):
    return {"json": json.dumps(document(options))}


def test_schema_is_valid_and_covers_the_sql_options(db):
    # Regex escapes must remain text after JSON decoding, not become lone surrogates.
    json.dumps(SCHEMA, ensure_ascii=False).encode("utf-8")
    Draft202012Validator.check_schema(SCHEMA)
    for name, parameters in db.execute("""SELECT function_name, parameters FROM duckdb_functions()
            WHERE function_name IN ('gatekeeper_configure', 'gatekeeper_validate')""").fetchall():
        # DuckDB 2.0 names a table function's positional parameters col0.. in duckdb_functions() ahead of the
        # description's names (GetParameterNames); 1.5 used the description's.
        assert set(SCHEMA["properties"]["options"]["properties"]) == set(parameters) - {"sql", "col0", "json"}, name


VALID_OPTIONS = [
    {}, {"use_default_functions": False}, {"allowed_functions": ["ABS", "abs", "+", "*", "λ", "a\nb"]},
    {"blocked_functions": ["MD5"]}, {"allowed_functions": [], "blocked_functions": []},
    {"allowed_tables": []}, {"blocked_tables": []},
    {"allowed_tables": [{"schema_path": ["MAIN"], "table": "t"}]},
    {"allowed_tables": [{"catalog": None, "schema_path": ["main"], "table": "t"}]},
    {"allowed_tables": [{"catalog": "memory", "schema_path": ["main"], "table": "t"},
                        {"schema_path": ["main"], "table": "secret"}]},
    {"blocked_tables": [{"catalog": "*", "schema_path": ["*"], "table": "secret"}]},
    {"use_default_functions": False, "allowed_functions": ["abs"], "blocked_functions": ["md5"],
     "allowed_tables": [{"schema_path": ["main"], "table": "*"}],
     "blocked_tables": [{"schema_path": ["main"], "table": "secret"}]},
    {"allowed_tables": [{"schema_path": ["finance", "reports"], "table": "t"}]},
]


@pytest.mark.parametrize("options", VALID_OPTIONS)
def test_json_and_typed_configuration_and_results_are_equivalent(db, options):
    SCHEMA_VALIDATOR.validate(document(options))
    db.execute("CREATE TABLE t(x INT); CREATE TABLE secret(x INT)")
    statements = ["SELECT 1", "SELECT abs(-1)", "SELECT md5('x')", "SELECT * FROM t", "SELECT * FROM secret",
                  "SELECT * FROM missing", "SELECT * FROM", "DROP TABLE t", None]
    for sql in statements:
        assert validate(db, sql, encoded(options)) == validate(db, sql, options)
    assert configure(db, options)
    expected = policy(db)
    results = [validate(db, sql) for sql in statements]
    configure(db)
    assert configure(db, encoded(options))
    assert policy(db) == expected
    assert [validate(db, sql) for sql in statements] == results


def schema_cases():
    """Mutate each schema level, including every option and identity field."""
    yield document({}), True
    yield {"$schema": SCHEMA["$id"], **document({})}, True
    yield {"version": 2.0, "options": {}}, True  # JSON Schema integers include integral numbers.
    for value in [None, [], True, 1, "policy", {}, {"version": 2}, {"options": {}},
                  {"version": 1, "options": {}}, {"version": True, "options": {}},
                  {"version": "1", "options": {}}, {"version": 1.5, "options": {}},
                  {"version": 2, "options": None}, {"version": 2, "options": []},
                  {**document({}), "extra": 1}, {**document({}), "$schema": None},
                  {**document({}), "$schema": "https://example.com/other.json"}]:
        yield value, False
    for name in ["unknown", "json", "restrict_tables", "max_statements", "ALLOWED_TABLES", "allowed_tables\0"]:
        yield document({name: []}), False
    for value in [None, 0, 1, "false", [], {}]:
        yield document({"use_default_functions": value}), False
    for name in ["allowed_functions", "blocked_functions"]:
        for value in [None, "md5", {}, True, [None], [1], [True], [{}], [[]], [""], ["a\0b"], ["\0\n"],
                      ["\ud800"], ["\udfff"], ["a\ud800b"], ["\udc00\ud800"]]:
            yield document({name: value}), False
        for value in [[], ["a", "a"], ["\n"], ["*"], ["a\nb"], ["😀"], ["\ud83d\ude00"]]:
            yield document({name: value}), True
    for name in ["allowed_tables", "blocked_tables"]:
        for value in [None, {}, "main.t", [None], [1], ["main.t"], [[]], [{}],
                      [{"schema_path": ["main"]}], [{"table": "t"}],
                      [{"schema": "main", "table": "t"}],
                      [{"schema_path": ["main"], "table": "t", "catlog": "memory"}]]:
            yield document({name: value}), False
        for field in ["catalog", "table"]:
            for value in [None, "", "a\0b", 1, True, [], {}, "*", "λ", "a'b", "a\nb", "😀",
                          "\ud800", "\udfff", "a\ud800b"]:
                entry = {"schema_path": ["main"], "table": "t", field: value}
                valid = (field == "catalog" and value is None) or (
                    isinstance(value, str) and value != "" and "\0" not in value
                    and not any(0xD800 <= ord(c) <= 0xDFFF for c in value))
                yield document({name: [entry]}), valid
        for value in [None, "main", [], [None], [1], [[]], [""], ["a\0b"], ["\ud800"], ["main", None]]:
            yield document({name: [{"schema_path": value, "table": "t"}]}), False
        for value in [["main"], ["finance", "reports"], ["a.b"], ["*", "reports"], ["a", "a"], ["😀"]]:
            yield document({name: [{"schema_path": value, "table": "t"}]}), True


@pytest.mark.parametrize("value,accepted", list(schema_cases()))
def test_schema_and_both_decoders_agree(db, value, accepted):
    assert SCHEMA_VALIDATOR.is_valid(value) is accepted
    configure(db, {"blocked_functions": ["md5"]})
    before = policy(db)
    arguments = {"json": json.dumps(value)}
    result = validate(db, "SELECT 1", arguments)
    assert result["code"] == ("ok" if accepted else "invalid_input"), result
    if accepted:
        assert configure(db, arguments)
    else:
        with pytest.raises(duckdb.BinderException):
            configure(db, arguments)
        assert policy(db) == before


@pytest.mark.parametrize("text", [
    None, "", "{", "{} {}", '{"version":2,"options":{},}',
    '{/* comment */"version":2,"options":{}}', '{"version":NaN,"options":{}}',
    '{"version":2,"options":{},"version":2}',
    '{"version":2,"options":{},"options":{}}',
    '{"version":2,"options":{"blocked_functions":[],"blocked_functions":["md5"]}}',
    '{"version":2,"options":{"blocked_functions":[],"blocked_\\u0066unctions":["md5"]}}',
    '{"version":2,"options":{"allowed_tables":[{"schema_path":["main"],"table":"t","catalog":"a","catalog":"b"}]}}',
    '{"version":2,"options":{"allowed_functions":["\\ud800"]}}',
    '{"version":2,"options":{}}\0',
])
def test_invalid_json_text_fails_closed(db, text):
    configure(db, {"blocked_functions": ["md5"]})
    before = policy(db)
    result = validate(db, "SELECT 1", {"json": text})
    assert result["code"] == "invalid_input" and not result["allowed"]
    assert result["error_message"]
    with pytest.raises(duckdb.BinderException):
        configure(db, {"json": text})
    assert policy(db) == before


@pytest.mark.parametrize("extra", [{"use_default_functions": True}, {"allowed_functions": []},
                                   {"blocked_functions": None}, {"allowed_tables": []}, {"blocked_tables": []}])
def test_json_is_mutually_exclusive_even_with_empty_or_null_options(db, extra):
    for operation in [lambda args: configure(db, args), lambda args: validate(db, "SELECT 1", args)]:
        with pytest.raises(duckdb.BinderException, match="mutually exclusive"):
            operation({**encoded({}), **extra})


@pytest.mark.parametrize("value", [1, True, [], {}, b"{}"])
def test_json_requires_text_without_implicit_casts(db, value):
    for operation in [lambda args: configure(db, args), lambda args: validate(db, "SELECT 1", args)]:
        with pytest.raises(duckdb.BinderException, match="json requires VARCHAR"):
            operation({"json": value})


def test_duplicate_json_argument_is_a_bind_error(db):
    for prefix in ["CALL gatekeeper_configure(", "SELECT * FROM gatekeeper_validate('SELECT 1', "]:
        with pytest.raises(duckdb.BinderException, match="duplicate Gatekeeper option"):
            db.execute(prefix + "json := '{}', json := '{}')")


def test_json_inherits_and_cannot_widen_the_current_global_policy(db):
    db.execute("CREATE TABLE t(x INT); CREATE TABLE secret(x INT)")
    configure(db, encoded({"blocked_functions": ["md5"], "allowed_tables": [{"schema_path": ["main"], "table": "t"}]}))
    for options in [{}, {"blocked_functions": [], "allowed_tables": [{"schema_path": ["*"], "table": "*"}]}]:
        assert validate(db, "SELECT md5('x')", encoded(options))["code"] == "forbidden"
        assert validate(db, "SELECT * FROM secret", encoded(options))["code"] == "forbidden"
        assert validate(db, "SELECT * FROM t", encoded(options))["allowed"]
    configure(db, encoded({}))
    assert not policy(db)["restrict_tables"]
    assert validate(db, "SELECT * FROM secret")["allowed"]
    configure(db, encoded({"allowed_tables": []}))
    assert policy(db)["restrict_tables"]
    assert not validate(db, "SELECT * FROM t")["allowed"]


def test_prepared_json_validation_rechecks_policy_and_parameters(db):
    db.execute("PREPARE validation AS SELECT code FROM gatekeeper_validate($1, json := $2)")
    assert db.execute("EXECUTE validation('SELECT md5(''x'')', '{\"version\":2,\"options\":{}}')").fetchone() == ("ok",)
    configure(db, encoded({"blocked_functions": ["md5"]}))
    assert db.execute("EXECUTE validation('SELECT md5(''x'')', '{\"version\":2,\"options\":{}}')").fetchone() == ("forbidden",)
    assert db.execute("EXECUTE validation('SELECT 1', 'bad json')").fetchone() == ("invalid_input",)
    configure(db)
    assert db.execute("EXECUTE validation('SELECT md5(''x'')', '{\"version\":2,\"options\":{\"blocked_functions\":[\"md5\"]}}')").fetchone() == ("forbidden",)


def test_prepared_json_configuration_only_mutates_on_execution_and_obeys_lock(db):
    before = policy(db)
    db.execute("PREPARE cfg AS SELECT * FROM gatekeeper_configure(json := $1)")
    db.execute("PREPARE fixed AS SELECT * FROM gatekeeper_configure(json := '{\"version\":2,\"options\":{}}')")
    db.execute("EXPLAIN CALL gatekeeper_configure(json := '{\"version\":2,\"options\":{}}')")
    assert policy(db) == before
    # Unread on purpose: the configure runs when its statement runs, on either engine.
    db.execute("EXECUTE cfg('{\"version\":2,\"options\":{\"blocked_functions\":[\"md5\"]}}')")
    assert policy(db)["blocked_functions"] == ["md5"]
    db.execute("EXECUTE cfg('{\"version\":2,\"options\":{\"blocked_functions\":[\"lower\"]}}')")
    assert policy(db)["blocked_functions"] == ["lower"]
    db.execute("SET lock_configuration = true")
    for sql in ["EXECUTE cfg('{\"version\":2,\"options\":{}}')", "EXECUTE fixed"]:
        with pytest.raises(duckdb.Error, match="locked"):
            db.execute(sql)
    assert policy(db)["blocked_functions"] == ["lower"]


def test_json_configuration_shared_with_enforced_connections(db):
    with db.cursor() as agent:
        agent.execute("CALL gatekeeper_enforce()")
        configure(db, encoded({"blocked_functions": ["md5"]}))
        with pytest.raises(duckdb.PermissionException):
            agent.execute("SELECT md5('x')")
        with pytest.raises(duckdb.PermissionException):
            agent.execute("CALL gatekeeper_configure(json := '{\"version\":2,\"options\":{}}')")
        assert policy(db)["blocked_functions"] == ["md5"]


def test_json_uses_existing_audit_records(db):
    enable(db)
    options = {"blocked_functions": ["md5"]}
    configure(db, options)
    configure(db, encoded(options))
    changes = records(db, "event = 'policy_changed'")
    assert len(changes) == 2
    assert changes[0]["policy_hash"] == changes[1]["policy_hash"]
    assert changes[0]["new_value"] == changes[1]["new_value"]
    result = validate(db, "SELECT 1", {"json": "invalid"})
    [record] = decisions(db)
    assert record["code"] == result["code"] == "invalid_input"
    assert record["error_message"] == result["error_message"]


@pytest.mark.parametrize("options,path", [
    ({"allowed_functions": [1]}, "options.allowed_functions[0]"),
    ({"allowed_tables": [{"schema_path": ["main"], "table": 1}]}, "options.allowed_tables[0].table"),
    ({"allowed_tables": ["main.t"]}, "options.allowed_tables[0]"),
    ([], "options"),
])
def test_json_shape_diagnostics_identify_the_path(db, options, path):
    arguments = encoded(options)
    result = validate(db, "SELECT 1", arguments)
    assert result["code"] == "invalid_input"
    assert result["error_message"].startswith(path + ": expected JSON")
    with pytest.raises(duckdb.BinderException) as caught:
        configure(db, arguments)
    assert result["error_message"] in str(caught.value)
