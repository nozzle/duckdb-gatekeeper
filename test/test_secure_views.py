"""Secure-view authorization preserves the engine barrier and privileged host evidence."""
import duckdb
import pytest

from support.artifact import ENGINE_MAJOR, literal
from support.audit import decisions, enable
from support.enforcement import enforce, settle
from support.typed_helpers import configure, rule, validate


pytestmark = pytest.mark.skipif(ENGINE_MAJOR < 2, reason="Secure views require DuckDB 2.0")


def identity(schema, name, kind="table"):
    return {"catalog": "memory", "schema_path": [schema], "table": name, "type": kind}


@pytest.fixture
def secure(db):
    db.execute("CREATE SCHEMA hidden; CREATE SCHEMA exposed; "
               "CREATE TABLE hidden.payload AS SELECT * FROM (VALUES (1, '12'), (2, 'secret')) t(i, s); "
               "CREATE SECURE VIEW exposed.direct AS SELECT i, s, md5(s) AS digest FROM hidden.payload WHERE i = 1; "
               "CREATE VIEW exposed.regular AS SELECT * FROM exposed.direct; "
               "CREATE SECURE VIEW exposed.nested AS SELECT * FROM exposed.regular; "
               "CREATE SECURE VIEW exposed.generated AS SELECT * FROM range(2)")
    configure(db, {"allowed_tables": [rule(schema_path=["exposed"])],
                   "blocked_tables": [rule(schema_path=["hidden"])], "blocked_functions": ["md5", "range"]})
    return db


@pytest.mark.parametrize("name,views", [("direct", ["direct"]), ("regular", ["direct", "regular"]),
                                      ("nested", ["direct", "nested", "regular"])])
def test_secure_view_identity_and_transitive_trusted_evidence(secure, name, views):
    result = validate(secure, f"SELECT * FROM exposed.{name}")
    assert result["allowed"], result
    assert result["caller_objects"] == [identity("exposed", name, "view")]
    assert result["objects"] == [identity("exposed", v, "view") for v in views] + [identity("hidden", "payload")]
    assert any(f["name"] == "md5" for f in result["functions"])
    assert not validate(secure, f"SELECT * FROM exposed.{name}",
                        {"blocked_tables": [rule(schema_path=["exposed"], table=name)]})["allowed"]
    assert not validate(secure, f"SELECT * FROM exposed.{name}",
                        {"allowed_tables": [rule(catalog="other", schema_path=["exposed"])]})["allowed"]


def test_hidden_reader_and_caller_function_are_distinguished(secure):
    assert validate(secure, "SELECT * FROM exposed.generated")["allowed"]
    assert validate(secure, "SELECT * FROM exposed.direct WHERE md5(s) = digest")["code"] == "forbidden"
    # The caller function is still caller-attributable when the optimizer can push its predicate below
    # the secure boundary. It must be admitted explicitly, even if the body uses the same function.
    configure(secure, {"allowed_tables": [rule(schema_path=["exposed"])], "allowed_functions": ["md5"]})
    sql = "SELECT i FROM exposed.direct WHERE md5(s) = digest"
    assert validate(secure, sql)["allowed"]
    with secure.cursor() as agent:
        enforce(agent)
        assert agent.execute(sql).fetchall() == [(1,)]
        configure(secure, {"allowed_tables": [rule(schema_path=["exposed"])], "blocked_functions": ["md5"]})
        with pytest.raises(duckdb.PermissionException, match="Gatekeeper denied"):
            agent.execute(sql)


@pytest.mark.parametrize("sql", [
    "SELECT * FROM exposed.direct, hidden.payload",
    # No direct lookup of hidden.payload: the CTE reference alone matches the hidden table query-wide.
    "WITH payload AS (SELECT 1) SELECT * FROM exposed.direct, payload",
])
def test_caller_objects_is_conservative_not_a_public_diagnostics_projection(secure, sql):
    denied = validate(secure, sql)
    assert denied["code"] == "forbidden"
    assert denied["objects"] == denied["functions"] == denied["caller_objects"] == []
    assert any(v["table"] == "payload" for v in denied["violations"])
    configure(secure, {"allowed_tables": [rule(schema_path=["exposed"]), rule(schema_path=["hidden"])],
                       "blocked_functions": ["md5"]})
    result = validate(secure, sql)
    assert result["allowed"], result
    assert identity("hidden", "payload") in result["caller_objects"]


@pytest.mark.parametrize("sql,rows,allowed", [
    ("SELECT i FROM exposed.direct", [(1,)], True),
    ("SELECT a.i, b.i FROM exposed.nested a, exposed.direct b WHERE a.i = b.i", [(1, 1)], True),
    ("SELECT * FROM exposed.generated a, exposed.generated b ORDER BY a.range, b.range",
     [(0, 0), (0, 1), (1, 0), (1, 1)], True),
    ("SELECT i FROM exposed.direct WHERE abs(i) = 1", [(1,)], True),
    ("SELECT i FROM exposed.direct WHERE md5(s) = digest", [(1,)], False),
    ("SELECT * FROM hidden.payload ORDER BY i", [(1, "12"), (2, "secret")], False),
])
@pytest.mark.parametrize("log_only", [False, True])
def test_private_and_execution_scan_accounting_audit_and_log_only_parity(secure, sql, rows, allowed, log_only):
    expected = validate(secure, sql)
    assert expected["allowed"] is allowed, expected
    enable(secure, "debug")
    secure.execute(f"SET gatekeeper_log_only = {str(log_only).lower()}")
    with secure.cursor() as agent:
        enforce(agent)
        if expected["allowed"] or log_only:
            assert agent.execute(sql).fetchall() == rows
        else:
            with pytest.raises(duckdb.PermissionException, match="Gatekeeper denied"):
                agent.execute(sql)
        settle(agent)
    mode = "log_only" if log_only else "enforce"
    [record] = decisions(secure, f"mode = '{mode}' AND statement = {literal(sql)}")
    for column in ["allowed", "code", "violations", "objects", "functions", "caller_objects"]:
        assert record[column] == expected[column], (column, record, expected)
    if expected["allowed"]:
        assert record["boundary"] == "execution"


def test_engine_predicate_barrier_survives_enforcement(secure):
    # An error-capable caller predicate must never see the row removed inside the secure view.
    sql = "SELECT i FROM exposed.direct WHERE CAST(s AS INTEGER) = 12"
    assert secure.execute(sql).fetchall() == [(1,)]
    assert validate(secure, sql)["allowed"]
    with secure.cursor() as agent:
        enforce(agent)
        assert agent.execute(sql).fetchall() == [(1,)]
        assert agent.execute("SELECT i FROM exposed.direct WHERE CAST(s AS INTEGER) = ?", [12]).fetchall() == [(1,)]
        plan = agent.execute("EXPLAIN " + sql).fetchone()[1]
        assert "SECURE_VIEW" in plan
        assert "payload" not in plan and "hidden" not in plan


def test_secure_boundary_does_not_hide_gatekeeper_control_plane(secure):
    secure.execute("CREATE SECURE VIEW exposed.control AS SELECT * FROM gatekeeper_configure()")
    sql = "SELECT * FROM exposed.control"
    result = validate(secure, sql)
    assert result["code"] == "forbidden", result
    assert any(v["function_name"] == "gatekeeper_configure" for v in result["violations"])
    with secure.cursor() as agent:
        enforce(agent)
        with pytest.raises(duckdb.PermissionException, match="Gatekeeper denied"):
            agent.execute(sql)


@pytest.mark.parametrize("log_only", [False, True])
def test_missing_dependency_diagnostics_remain_host_only(secure, log_only):
    secure.execute("DROP TABLE hidden.payload")
    sql = "SELECT * FROM exposed.direct"
    # The tested engine does not sanitize binding errors from a secure body: it names the missing table.
    with pytest.raises(duckdb.CatalogException, match="payload") as plain:
        secure.execute(sql)
    result = validate(secure, sql)
    assert result["code"] == "binding", result
    assert "payload" in result["error_message"]
    assert result["objects"] == result["functions"] == result["caller_objects"] == []
    enable(secure, "debug")
    secure.execute(f"SET gatekeeper_log_only = {str(log_only).lower()}")
    with secure.cursor() as agent:
        enforce(agent)
        with pytest.raises(duckdb.CatalogException) as logged:
            agent.execute(sql)
    assert str(logged.value) == str(plain.value)
    if log_only:
        [record] = decisions(secure, "mode = 'log_only'")
        assert record["error_message"] == result["error_message"]
        assert record["code"] == "binding"
    else:
        # In enforcement mode engine binding failures propagate without becoming policy decisions.
        assert decisions(secure, "mode = 'enforce'") == []
