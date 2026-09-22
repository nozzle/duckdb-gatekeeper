"""Successful caller-attributable catalog evidence, separate from trusted expansion."""
import pytest

from support.audit import decisions, enable
from support.enforcement import enforce
from support.typed_helpers import configure, validate


def identity(name, kind="table", catalog="memory", schema="main"):
    return {"catalog": catalog, "schema": schema, "table": name, "type": kind}


def rules(*names):
    return [{"catalog": "memory", "schema": "main", "table": name} for name in names]


@pytest.fixture
def chain(db):
    db.execute("""CREATE TABLE c(id INTEGER); INSERT INTO c VALUES (1);
        CREATE VIEW b AS SELECT * FROM c;
        CREATE VIEW nested_b AS SELECT * FROM b;
        CREATE MACRO m() AS TABLE SELECT * FROM b;
        CREATE MACRO scalar_m() AS (SELECT count(*) FROM b)""")
    configure(db, {"allowed_functions": ["m", "scalar_m"]})
    return db


@pytest.mark.parametrize("sql, expected", [
    ("SELECT * FROM b", [identity("b", "view")]),
    ("SELECT * FROM nested_b", [identity("nested_b", "view")]),
    ("SELECT * FROM b JOIN c USING (id)", [identity("b", "view"), identity("c")]),
    ("SELECT * FROM c JOIN b USING (id)", [identity("b", "view"), identity("c")]),
    ("SELECT * FROM b x, b y", [identity("b", "view")]),
    ("WITH x AS (SELECT * FROM b) SELECT * FROM x", [identity("b", "view")]),
    ("WITH x AS (SELECT * FROM c) SELECT * FROM b", [identity("b", "view"), identity("c")]),
    ("WITH unused AS (SELECT * FROM c) SELECT 1", []),
    ("SELECT * FROM m()", []),
    ("SELECT scalar_m()", []),
    ("SELECT * FROM m(), b", [identity("b", "view")]),
    ("SELECT * FROM range(2)", []),
])
def test_caller_objects_are_a_sorted_deduplicated_subset(chain, sql, expected):
    result = validate(chain, sql)
    assert result["allowed"], result
    assert result["caller_objects"] == expected
    assert all(entry in result["objects"] for entry in expected)


def test_declared_input_contract(chain):
    declared = rules("b", "nested_b")
    result = validate(chain, "SELECT * FROM b", {"allowed_tables": declared})
    assert result["allowed"] and result["caller_objects"] == [identity("b", "view")]
    assert result["objects"] == [identity("b", "view"), identity("c")]
    # An unused declaration is visible on success; an undeclared caller reference still fails fast.
    denied = validate(chain, "SELECT * FROM b JOIN c USING (id)", {"allowed_tables": declared})
    assert denied["code"] == "forbidden" and denied["violations"][0]["table"] == "c"
    assert denied["caller_objects"] == denied["objects"] == []


def test_cte_collision_is_conservative_attribution(chain):
    result = validate(chain, "WITH c AS (SELECT 1 AS id) SELECT * FROM b, c")
    assert result["allowed"]
    assert result["caller_objects"] == [identity("b", "view"), identity("c")]
    # Alias declarations and an unrelated CTE reference do not attribute the view's dependency.
    for sql in ["SELECT c.id FROM b AS c", "WITH x AS (SELECT 1 AS id) SELECT * FROM b, x"]:
        assert validate(chain, sql)["caller_objects"] == [identity("b", "view")]


def test_resolved_identity_preserves_case_qualification_and_shadowing(db):
    db.execute('''ATTACH ':memory:' AS lake; CREATE SCHEMA lake."a.b";
        CREATE TABLE lake."a.b"."T.X"(id INTEGER);
        CREATE TABLE t(id INTEGER); CREATE TEMP TABLE t(id INTEGER)''')
    result = validate(db, 'SELECT * FROM lake."a.b"."t.x" a, LAKE."a.b"."T.X" b')
    assert result["allowed"] and result["caller_objects"] == [identity("T.X", catalog="lake", schema="a.b")]
    assert validate(db, "SELECT * FROM t")["caller_objects"] == [identity("t", catalog="temp")]
    assert validate(db, "SELECT * FROM memory.main.t")["caller_objects"] == [identity("t")]


@pytest.mark.parametrize("sql, options", [
    ("SELECT * FROM b, missing", {}),
    ("SELECT * FROM b", {"allowed_tables": []}),
    ("SELECT md5('x') FROM b", {"blocked_functions": ["md5"]}),
    ("SELECT * FROM", {}),
    ("DROP TABLE c", {}),
    (None, {}),
])
def test_failure_never_exposes_partial_caller_evidence(chain, sql, options):
    result = validate(chain, sql, options)
    assert not result["allowed"] and result["caller_objects"] == []


def test_replacement_capabilities_are_not_catalog_inputs(db, tmp_path):
    path = str(tmp_path / "input.parquet").replace("'", "''")
    db.execute(f"COPY (SELECT 1 AS id) TO '{path}' (FORMAT PARQUET)")
    configure(db, {"allowed_functions": ["read_parquet"]})
    result = validate(db, f"SELECT * FROM '{path}'")
    assert result["allowed"] and result["caller_objects"] == []
    assert any(o["type"] == "replacement" for o in result["objects"])
    assert any(f["name"] in {"read_parquet", "parquet_scan"} for f in result["functions"])


def test_prepared_validation_and_audit_share_caller_evidence(chain):
    enable(chain, "debug")
    chain.execute("PREPARE validation AS SELECT caller_objects FROM gatekeeper_validate($1)")
    assert chain.execute("EXECUTE validation('SELECT * FROM b')").fetchone()[0] == [identity("b", "view")]
    assert chain.execute("EXECUTE validation('SELECT * FROM c')").fetchone()[0] == [identity("c")]
    sql = "SELECT * FROM b WHERE id > ?"
    with chain.cursor() as agent:
        enforce(agent)
        agent.executemany(sql, [[0], [0]])
        assert agent.fetchall() == [(1,)]
    found = decisions(chain, "mode = 'enforce'")
    assert len(found) == 2
    assert all(r["caller_objects"] == [identity("b", "view")] for r in found)
    assert all(r["objects"] == [identity("b", "view"), identity("c")] for r in found)
    configure(chain, {"allowed_tables": []})
    denied = validate(chain, "SELECT * FROM b")
    assert denied["caller_objects"] == []
    assert decisions(chain, "mode = 'validate'")[-1]["caller_objects"] == []
