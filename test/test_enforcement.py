"""Enforced connections: the engine refuses what gatekeeper_validate would deny, without host glue."""
import concurrent.futures
import os
import re
import threading

import duckdb
import pytest

from test_gatekeeper import EXTENSION, connect, db
from typed_helpers import configure, validate

DENIED = re.compile(r"Gatekeeper denied this statement")


def enforce(connection):
    row = connection.execute("CALL gatekeeper_enforce()").fetchone()
    assert row[0] is True
    return row[1]


CATALOG_SQL = """CREATE SCHEMA reporting; CREATE SCHEMA secret;
    CREATE TABLE reporting.orders(id INTEGER, amount DOUBLE, tag VARCHAR);
    INSERT INTO reporting.orders VALUES (1, 10.5, 'a'), (2, 20.25, 'b'), (3, 5.0, 'a');
    CREATE TABLE secret.salaries(who VARCHAR, amount DOUBLE);
    INSERT INTO secret.salaries VALUES ('x', 1.0);
    CREATE VIEW reporting.totals AS SELECT tag, sum(amount) AS total FROM reporting.orders GROUP BY tag;
    CREATE VIEW reporting.leak AS SELECT * FROM secret.salaries;
    CREATE MACRO reporting.twice(x) AS x * 2;
    CREATE SEQUENCE reporting.seq;
    CREATE TYPE tags AS ENUM ('a', 'b');
    CREATE TYPE empty_tags AS ENUM (SELECT tag FROM reporting.orders WHERE false)"""
CATALOG_POLICY = {"allowed_tables": [{"schema": "reporting", "table": "*"}],
                  "allowed_functions": ["twice"], "blocked_functions": ["md5"]}


@pytest.fixture
def catalog(db):
    db.execute(CATALOG_SQL)
    configure(db, CATALOG_POLICY)
    return db


@pytest.fixture
def agent(catalog):
    with catalog.cursor() as cursor:
        enforce(cursor)
        yield cursor


# Statement text paired with what gatekeeper_validate says about it; the oracle below asserts the engine
# agrees on an enforced connection. Rows read only reporting.* under the fixture policy.
PARITY_CORPUS = [
    "SELECT 1",
    "SELECT sum(amount), tag FROM reporting.orders GROUP BY tag ORDER BY 2",
    "SELECT * FROM reporting.totals",
    "SELECT twice(amount) FROM reporting.orders",
    "WITH t AS (SELECT id FROM reporting.orders) SELECT count(*) FROM t",
    "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5) SELECT sum(n) FROM r",
    "SELECT o.id, t.total FROM reporting.orders o JOIN reporting.totals t USING (tag)",
    "SELECT id, row_number() OVER (PARTITION BY tag ORDER BY amount) FROM reporting.orders",
    "SELECT id FROM reporting.orders UNION SELECT id + 10 FROM reporting.orders",
    "SELECT id FROM reporting.orders EXCEPT SELECT 1",
    "SELECT unnest([1, 2, 3])",
    "SELECT list_transform([1, 2], x -> x + 1)",
    "SELECT [1, 2, 3][2], {'a': 1}.a, 'x' || 'y'",
    "SELECT * FROM reporting.orders USING SAMPLE 1",
    "SELECT * FROM (SELECT tag, amount FROM reporting.orders) PIVOT (sum(amount) FOR tag IN ('a', 'b'))",
    "PIVOT reporting.orders ON tag USING sum(amount)",
    "PIVOT reporting.orders ON tag IN (SELECT DISTINCT tag FROM reporting.orders) USING sum(amount)",
    "PIVOT reporting.orders ON tag, id USING sum(amount) GROUP BY amount",
    "PIVOT reporting.orders ON tag IN tags, id USING count(*)",
    "PIVOT reporting.orders ON tag IN empty_tags, id USING count(*) GROUP BY amount",
    "PIVOT (PIVOT reporting.orders ON tag USING sum(amount) GROUP BY id) ON id USING count(*)",
    "WITH p AS (PIVOT reporting.orders ON tag USING sum(amount) GROUP BY id) PIVOT p ON id USING count(*)",
    "WITH c AS (SELECT * FROM reporting.orders) PIVOT c ON tag USING sum(amount)",
    "SELECT (SELECT count(*) FROM (PIVOT reporting.orders ON tag USING sum(amount)))",
    "SELECT 1 UNION ALL SELECT count(*) FROM (PIVOT reporting.orders ON tag USING sum(amount))",
    "SELECT * FROM reporting.orders PIVOT (sum(amount) FOR tag IN (SELECT tag FROM reporting.orders))",
    "SELECT DISTINCT tag FROM reporting.orders LIMIT 5 OFFSET 0",
    "SELECT * FROM reporting.orders WHERE amount > (SELECT avg(amount) FROM reporting.orders)",
    "SELECT * FROM reporting.orders o WHERE EXISTS (SELECT 1 FROM reporting.orders i WHERE i.id = o.id + 1)",
    "SELECT list_aggregate([1, 2], 'sum')",
    "DESCRIBE reporting.orders",
    "SHOW reporting.orders",
    "VALUES (1), (2)",
    "FROM reporting.orders SELECT id",
    "SELECT * FROM range(3)",
    "SELECT * FROM generate_series(1, 3)",
    "SELECT lower('A'), upper('b'), strftime(DATE '2024-01-01', '%Y')",
    # Denied by policy.
    "SELECT md5('x')",
    "SELECT * FROM secret.salaries",
    "SELECT * FROM reporting.leak",
    "SELECT who FROM reporting.leak",
    "SELECT * FROM reporting.orders, secret.salaries",
    "WITH s AS (SELECT * FROM secret.salaries) SELECT * FROM s",
    "SELECT (SELECT amount FROM secret.salaries LIMIT 1)",
    "SELECT nextval('reporting.seq')",
    "SELECT * FROM duckdb_tables()",
    "SELECT * FROM duckdb_settings()",
    "SELECT current_setting('threads')",
    "SELECT * FROM read_csv('/nonexistent/x.csv')",
    "SELECT * FROM read_parquet('/nonexistent/x.parquet')",
    "FROM '/nonexistent/x.parquet'",
    "SELECT * FROM query('SELECT 1')",
    "SELECT * FROM query_table('reporting.orders')",
    "SELECT * FROM json_execute_serialized_sql('{}')",
    "SELECT list_aggregate([1, 2], 'md5')",
    "SELECT * FROM reporting.orders LIMIT (SELECT 1)",
    # Dynamic PIVOT: the enum type's SELECT and the pivoting SELECT are each decided as the engine runs them.
    "PIVOT secret.salaries ON who USING sum(amount)",
    "PIVOT reporting.leak ON who USING sum(amount)",
    "PIVOT reporting.orders ON md5(tag) USING sum(amount)",
    "PIVOT reporting.orders ON tag USING sum(amount), md5(tag)",
    "PIVOT reporting.orders ON tag IN (SELECT who FROM secret.salaries) USING sum(amount)",
    "PIVOT reporting.orders ON tag IN (SELECT md5('x')) USING sum(amount)",
    "PIVOT reporting.orders ON tag USING sum(amount) LIMIT (SELECT 1)",
    "PIVOT (PIVOT reporting.leak ON who USING sum(amount) GROUP BY amount) ON amount USING count(*)",
    "PIVOT (PIVOT reporting.orders ON tag USING sum(amount) GROUP BY id) ON id USING count(*), md5(id)",
    # Only the parser's own rewrite of a dynamic PIVOT is a supported CREATE.
    "CREATE OR REPLACE TEMP TYPE \"__pivot_enum_0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\" AS ENUM (SELECT DISTINCT tag FROM reporting.orders)",
    "CREATE OR REPLACE TEMP TYPE \"__pivot_enum_0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\" AS ENUM (SELECT who FROM secret.salaries)",
    "CREATE OR REPLACE TEMP TYPE \"__pivot_enum_0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\" AS ENUM ('a', 'b')",
    "CREATE OR REPLACE TEMP TYPE \"__pivot_enum_notauuid\" AS ENUM (SELECT DISTINCT tag FROM reporting.orders)",
    "CREATE OR REPLACE TEMP TYPE mood AS ENUM (SELECT DISTINCT tag FROM reporting.orders)",
    "CREATE OR REPLACE TYPE \"__pivot_enum_0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\" AS ENUM (SELECT DISTINCT tag FROM reporting.orders)",
    "CREATE TEMP TYPE \"__pivot_enum_0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\" AS ENUM (SELECT DISTINCT tag FROM reporting.orders)",
    "CREATE OR REPLACE TEMP TYPE temp.main.\"__pivot_enum_0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\" AS ENUM (SELECT DISTINCT tag FROM reporting.orders)",
    "CREATE OR REPLACE TEMP TYPE \"__pivot_enum_0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\" AS INTEGER",
    "SHOW TABLES",
    "SELECT * FROM gatekeeper_validate('SELECT 1')",
    "SELECT * FROM gatekeeper_enforce()",
    # Unsupported statement types.
    "CREATE TABLE u(x INTEGER)",
    "CREATE OR REPLACE VIEW reporting.v2 AS SELECT 1",
    "INSERT INTO reporting.orders VALUES (9, 1.0, 'z')",
    "UPDATE reporting.orders SET amount = 0",
    "DELETE FROM reporting.orders",
    "DROP TABLE reporting.orders",
    "ALTER TABLE reporting.orders ADD COLUMN y INTEGER",
    "COPY reporting.orders TO '/tmp/gatekeeper_enforcement_test.csv'",
    "EXPORT DATABASE '/tmp/gatekeeper_enforcement_export'",
    "ATTACH ':memory:' AS other",
    "SET threads = 1",
    "RESET threads",
    "CALL pragma_version()",
    "LOAD json",
    "INSTALL json",
    "EXPLAIN SELECT 1",
    "EXPLAIN ANALYZE SELECT 1",
    "PREPARE p AS SELECT 1",
    "BEGIN TRANSACTION",
    "CHECKPOINT",
    "VACUUM",
    "CREATE SECRET s (TYPE s3)",
    "CALL gatekeeper_configure()",
    "CALL gatekeeper_enforce()",
    "RESET gatekeeper_policy",
    # Engine errors, which the engine reports in its own words.
    "SELECT * FROM reporting.missing",
    "SELECT no_such_column FROM reporting.orders",
    "SELECT no_such_function(1)",
    "SELECT 1 + 'a'::DATE",
    "PIVOT reporting.missing ON tag USING sum(amount)",
    "PIVOT reporting.orders ON no_such_column USING sum(amount)",
    "PIVOT reporting.orders ON tag USING sum(no_such_column)",
    # Static IN lists whose product alone passes pivot_limit (2^17 > 100000): the engine refuses the pivot.
    "PIVOT reporting.orders ON tag, " + ", ".join(f"id + {i} IN (1, 2)" for i in range(17)) + " USING count(*)",
]


@pytest.mark.parametrize("sql", PARITY_CORPUS)
def test_enforcement_agrees_with_validate(catalog, agent, sql):
    expected = validate(catalog, sql)
    try:
        agent.execute(sql).fetchall()
    except duckdb.Error as error:
        # Validation binds but never executes, so an allowed statement may still fail at runtime
        # (a bad cast, for instance). What it must never do is trip a Gatekeeper denial.
        assert not expected["allowed"] or not DENIED.search(str(error)), (sql, error)
        if expected["code"] in {"forbidden", "unsupported"}:
            assert isinstance(error, duckdb.PermissionException) and DENIED.search(str(error)), (sql, error)
        elif not expected["allowed"]:
            assert expected["code"] in {"binding", "parser"} and not DENIED.search(str(error)), (sql, expected, error)
        return
    assert expected["allowed"], (sql, expected)


def test_pragmas_are_checked_as_the_statements_duckdb_rewrites_them_into(catalog, agent):
    # DuckDB's statement preprocessor turns query pragmas into SELECTs and assignment pragmas into SETs
    # before any extension hook runs, so an enforced connection checks the rewritten statement. That is
    # policy-consistent: PRAGMA version is exactly SELECT * FROM pragma_version(), which the caller could
    # write directly. gatekeeper_validate sees the raw text and reports PRAGMA as unsupported.
    assert validate(catalog, "PRAGMA version")["code"] == "unsupported"
    assert validate(catalog, "SELECT * FROM pragma_version()")["allowed"]
    assert agent.execute("PRAGMA version").fetchall() == catalog.execute("SELECT * FROM pragma_version()").fetchall()
    configure(catalog, {"allowed_tables": [{"schema": "reporting", "table": "*"}],
                        "blocked_functions": ["pragma_version"]})
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("PRAGMA version").fetchall()
    for pragma in ["PRAGMA table_info('reporting.orders')", "PRAGMA show_tables", "PRAGMA database_list",
                   "PRAGMA storage_info('reporting.orders')", "PRAGMA threads = 1", "PRAGMA enable_verification",
                   "PRAGMA enable_profiling"]:
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(pragma).fetchall()


def test_dynamic_pivot_is_checked_as_the_statements_duckdb_rewrites_it_into(catalog, agent):
    # DuckDB's parser turns PIVOT ... ON col (no IN list) into CREATE OR REPLACE TEMP TYPE "__pivot_enum_<uuid>"
    # AS ENUM (SELECT DISTINCT col ...) followed by the SELECT that names the type, and the engine runs each as
    # its own statement. Gatekeeper admits exactly that CREATE, by shape, so the enum is created only from a
    # SELECT the policy allows and only in the connection's temporary catalog; gatekeeper_validate decides the
    # same statements in the same order and creates nothing.
    sql = "PIVOT reporting.orders ON tag USING sum(amount)"
    static = "PIVOT reporting.orders ON tag IN ('a', 'b') USING sum(amount)"
    assert validate(catalog, sql)["allowed"]
    assert agent.execute(sql).fetchall() == catalog.execute(static).fetchall()
    assert catalog.execute("SELECT count(*) FROM duckdb_types() WHERE type_name LIKE '__pivot_enum_%'").fetchone()[0] == 0
    # The pivoting SELECT is validated before the type exists, so it is bound against placeholder IN lists of
    # both sizes DuckDB plans differently: an aggregate FILTER per value up to pivot_filter_threshold, and a LIST
    # aggregate under a PIVOT operator above it. Blocking the LIST implementation denies the text as a whole, and
    # denies the statement at execution when the data selects that shape; the small-data case executes with an
    # aggregate FILTER plan that never binds it (the residual documented in docs/security.md).
    configure(catalog, dict(CATALOG_POLICY, blocked_functions=["list"]))
    result = validate(catalog, sql)
    assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "list", result
    assert agent.execute(sql).fetchall() == catalog.execute(static).fetchall()
    catalog.execute("CREATE TABLE reporting.wide AS SELECT i AS id, 'k' || i AS k, i * 1.5 AS v FROM range(40) t(i)")
    with pytest.raises(duckdb.PermissionException, match="list"):
        agent.execute("PIVOT reporting.wide ON k USING sum(v)").fetchall()
    catalog.execute("SET GLOBAL pivot_filter_threshold = 0")
    with pytest.raises(duckdb.PermissionException, match="list"):
        agent.execute(sql).fetchall()
    configure(catalog, CATALOG_POLICY)
    catalog.execute("RESET GLOBAL pivot_filter_threshold")
    # The large shape is sized per PIVOT from its static IN lists and host enums, so it stays under pivot_limit
    # wherever a legal LIST plan exists (here 11 * 2 = 22 < 30, where the threshold alone would give 21 * 2).
    catalog.execute("SET GLOBAL pivot_limit = 30")
    mixed = "PIVOT reporting.orders ON tag, id IN (1, 2) USING count(*)"
    assert validate(catalog, mixed)["allowed"]
    assert sorted(agent.execute(mixed).fetchall()) == sorted(catalog.execute(
        "PIVOT reporting.orders ON tag IN ('a', 'b'), id IN (1, 2) USING count(*)").fetchall())
    configure(catalog, dict(CATALOG_POLICY, blocked_functions=["list"]))
    assert validate(catalog, mixed)["violations"][0]["function_name"] == "list"
    configure(catalog, CATALOG_POLICY)
    catalog.execute("RESET GLOBAL pivot_limit")
    # An enum type's own SELECT can pivot dynamically too (a nested dynamic PIVOT): it is bound against
    # placeholders for the types created before it in the batch, like the final SELECT.
    nested = "PIVOT (PIVOT reporting.orders ON tag USING sum(amount) GROUP BY id) ON id USING count(*)"
    assert validate(catalog, nested)["allowed"]
    with catalog.cursor() as host:
        assert sorted(agent.execute(nested).fetchall(), key=repr) == sorted(host.execute(nested).fetchall(), key=repr)
    # An enum whose defining SELECT the policy denies is refused before the pivoting SELECT runs; a pivoting
    # SELECT the policy denies is refused after the engine created the enum, which is a temporary type in the
    # agent's own session and nothing more.
    for denied in ["PIVOT secret.salaries ON who USING sum(amount)",
                   "PIVOT reporting.orders ON tag IN (SELECT who FROM secret.salaries) USING sum(amount)",
                   "PIVOT reporting.orders ON tag USING sum(amount), md5(tag)"]:
        assert validate(catalog, denied)["code"] == "forbidden", denied
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(denied).fetchall()
    assert catalog.execute("SELECT count(*) FROM secret.salaries").fetchone()[0] == 1
    # The statement gatekeeper_validate reports on is the first the engine fails on: an enum SELECT that
    # cannot bind comes before a pivoting SELECT the policy would deny.
    result = validate(catalog, "PIVOT reporting.missing ON tag USING sum(amount), md5(tag)")
    assert result["code"] == "binding", result
    with pytest.raises(duckdb.CatalogException):
        agent.execute("PIVOT reporting.missing ON tag USING sum(amount), md5(tag)").fetchall()


def test_generated_nesting_agrees_with_validate(catalog, agent):
    import random
    rng = random.Random(4127)
    wrappers = [
        lambda q: f"SELECT * FROM ({q}) nested",
        lambda q: f"WITH local_cte AS ({q}) SELECT * FROM local_cte",
        lambda q: f"SELECT * FROM reporting.orders WHERE id IN (SELECT id FROM ({q}) x)",
        lambda q: f"SELECT * FROM reporting.orders UNION ALL SELECT id, amount, tag FROM ({q}) y",
    ]
    for _ in range(40):
        allowed = "SELECT id, amount, tag FROM reporting.orders"
        denied = "SELECT id, amount, who AS tag FROM (SELECT 1 id, amount, who FROM secret.salaries) z"
        for _ in range(rng.randrange(1, 5)):
            wrap = rng.choice(wrappers)
            allowed, denied = wrap(allowed), wrap(denied)
        assert validate(catalog, allowed)["allowed"], allowed
        agent.execute(allowed).fetchall()
        assert validate(catalog, denied)["code"] == "forbidden", denied
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(denied).fetchall()


def test_denied_before_binding_never_touches_readers(catalog, agent):
    # If the engine had bound these, the errors would be IO/HTTP errors about missing files, not denials.
    for sql in ["SELECT * FROM read_csv('/nonexistent/gatekeeper.csv')",
                "SELECT * FROM read_parquet('http://127.0.0.1:9/gatekeeper.parquet')",
                "FROM '/nonexistent/gatekeeper.parquet'",
                "FROM 'http://127.0.0.1:9/gatekeeper.csv'"]:
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql).fetchall()


def test_denied_statements_have_no_effect(catalog, agent):
    path = "/tmp/gatekeeper_enforcement_no_effect.csv"
    if os.path.exists(path):
        os.remove(path)
    before = catalog.execute("SELECT count(*) FROM duckdb_tables()").fetchone()[0]
    for sql in ["CREATE TABLE u AS SELECT * FROM reporting.orders",
                f"COPY reporting.orders TO '{path}'",
                "INSERT INTO reporting.orders VALUES (9, 1.0, 'z')",
                "CREATE TEMP TABLE tmp(x INTEGER)"]:
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql)
    assert catalog.execute("SELECT count(*) FROM duckdb_tables()").fetchone()[0] == before
    assert catalog.execute("SELECT count(*) FROM reporting.orders").fetchone()[0] == 3
    assert not os.path.exists(path)


def test_parameters_are_authorized_with_their_values(catalog, agent):
    assert agent.execute("SELECT id FROM reporting.orders WHERE amount > ?", [10]).fetchall() == [(1,), (2,)]
    assert agent.execute("SELECT $1::INTEGER + $2::INTEGER", [1, 2]).fetchone() == (3,)
    assert agent.execute("SELECT id FROM reporting.orders WHERE tag = $tag", {"tag": "b"}).fetchall() == [(2,)]
    # executemany rebinds every execution under the current policy.
    agent.executemany("SELECT id FROM reporting.orders WHERE id = ?", [[1], [2], [3]])
    assert agent.fetchall() == [(3,)]
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM secret.salaries WHERE amount > ?", [0]).fetchall()
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT md5(?)", ["x"]).fetchall()
    # A parameter cannot smuggle a reader or object name: it is a value, never SQL.
    assert agent.execute("SELECT ?", ["secret.salaries"]).fetchone() == ("secret.salaries",)


def test_relation_api_is_enforced(catalog, agent):
    assert agent.sql("SELECT sum(amount) FROM reporting.orders").fetchone() == (35.75,)
    assert agent.table("reporting.orders").filter("id > 2").fetchall() == [(3, 5.0, "a")]
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.sql("SELECT * FROM secret.salaries").fetchall()
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.table("secret.salaries").fetchall()
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.sql("SELECT * FROM duckdb_settings()").fetchall()
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.sql("CREATE TABLE q(x INTEGER)")


def test_each_statement_of_a_batch_is_checked(catalog, agent):
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT 1; CREATE TABLE q(x INTEGER); SELECT 2")
    assert catalog.execute("SELECT count(*) FROM duckdb_tables() WHERE table_name = 'q'").fetchone()[0] == 0
    assert agent.execute("SELECT 1; SELECT 2").fetchall() == [(2,)]


def test_latch_is_irreversible_and_unreachable_from_sql(catalog, agent):
    for sql in ["CALL gatekeeper_enforce()", "SELECT * FROM gatekeeper_enforce()",
                "SET GLOBAL gatekeeper_policy = current_setting('gatekeeper_policy')",
                "CALL gatekeeper_configure()"]:
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql)
    assert validate(catalog, "SELECT * FROM gatekeeper_enforce()", {"allowed_functions": ["gatekeeper_enforce"]})["code"] == "forbidden"
    # There is no instance-wide switch for a trusted connection to flip either.
    with pytest.raises(duckdb.CatalogException):
        catalog.execute("SET gatekeeper_enforcement = 'off'")
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("CREATE TABLE q(x INTEGER)")


def test_host_connection_is_unaffected(catalog, agent):
    catalog.execute("CREATE TABLE host_only(x INTEGER); INSERT INTO host_only VALUES (1)")
    assert catalog.execute("SELECT * FROM host_only").fetchall() == [(1,)]
    assert catalog.execute("EXPLAIN SELECT 1").fetchall()
    catalog.execute("PREPARE p AS SELECT $1::INTEGER")
    assert catalog.execute("EXECUTE p(7)").fetchone() == (7,)
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM host_only").fetchall()


def test_policy_changes_apply_to_the_next_statement(catalog, agent):
    assert agent.execute("SELECT sum(amount) FROM reporting.orders").fetchone() == (35.75,)
    configure(catalog, {"allowed_tables": [{"schema": "reporting", "table": "*"}], "blocked_functions": ["sum"]})
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT sum(amount) FROM reporting.orders").fetchall()
    configure(catalog, {"allowed_tables": [{"schema": "secret", "table": "*"}]})
    assert agent.execute("SELECT * FROM secret.salaries").fetchall() == [("x", 1.0)]
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM reporting.orders").fetchall()


def test_validate_is_available_when_allowed(catalog, agent):
    configure(catalog, {"allowed_tables": [{"schema": "reporting", "table": "*"}],
                        "allowed_functions": ["gatekeeper_validate"]})
    rows = agent.execute("SELECT allowed, code FROM gatekeeper_validate('SELECT * FROM secret.salaries')").fetchall()
    assert rows == [(False, "forbidden")]
    rows = agent.execute("SELECT allowed, code FROM gatekeeper_validate('SELECT count(*) FROM reporting.orders')").fetchall()
    assert rows == [(True, "ok")]
    # The request layer can only narrow the global policy, never widen it.
    rows = agent.execute("""SELECT allowed FROM gatekeeper_validate('SELECT * FROM secret.salaries',
                            allowed_tables := [{schema: 'secret', 'table': '*'}])""").fetchall()
    assert rows == [(False,)]


def test_trusted_expansions_stay_trusted(catalog, agent):
    catalog.execute("CREATE VIEW reporting.hashed AS SELECT md5(tag) AS h FROM reporting.orders")
    # md5 is blocked by name, so the trusted view is denied just as validate denies it...
    assert validate(catalog, "SELECT * FROM reporting.hashed")["code"] == "forbidden"
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("SELECT * FROM reporting.hashed").fetchall()
    # ...while a view over an elevated (non-default) function is allowed when the view is.
    catalog.execute("CREATE VIEW reporting.settings_count AS SELECT count(*) AS n FROM duckdb_settings()")
    assert validate(catalog, "SELECT * FROM reporting.settings_count")["code"] == "forbidden"  # never-bind
    catalog.execute("CREATE VIEW reporting.version AS SELECT * FROM pragma_version()")
    expected = validate(catalog, "SELECT library_version FROM reporting.version")
    if expected["allowed"]:
        assert agent.execute("SELECT library_version FROM reporting.version").fetchall()
    else:
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute("SELECT library_version FROM reporting.version").fetchall()


def test_explain_and_prepare_of_enforce_do_not_latch(db):
    db.execute("EXPLAIN SELECT * FROM gatekeeper_enforce()").fetchall()
    db.execute("PREPARE latch AS SELECT * FROM gatekeeper_enforce()")
    db.execute("CREATE TABLE still_host(x INTEGER)")
    db.execute("EXECUTE latch").fetchall()
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        db.execute("CREATE TABLE now_enforced(x INTEGER)")


def test_enforcement_is_per_connection(db):
    # A connection is enforced because gatekeeper_enforce() ran on it, and only then: connections open
    # before, connections opened afterwards, and the connection that created the enforced one are all
    # unaffected. Nothing about the instance changes.
    db.execute("CREATE TABLE t(x INTEGER)")
    with db.cursor() as older, db.cursor() as enforced:
        older.execute("SELECT 1")
        enforce(enforced)
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            enforced.execute("CREATE TABLE u(x INTEGER)")
        assert enforced.execute("SELECT count(*) FROM t").fetchone() == (0,)
        older.execute("CREATE TABLE u(x INTEGER)")
        db.execute("CREATE TABLE v(x INTEGER)")
        with db.cursor() as newer:
            newer.execute("CREATE TABLE w(x INTEGER)")
    assert db.execute("SELECT count(*) FROM duckdb_tables() WHERE table_name IN ('t', 'u', 'v', 'w')").fetchone() == (4,)


def test_enforce_is_not_a_setting(db):
    # The setting name that once existed is unknown to the engine, and gatekeeper_enforce() is a table
    # function, so lock_configuration neither blocks it nor is needed to keep it irreversible.
    with pytest.raises(duckdb.CatalogException):
        db.execute("SET gatekeeper_enforcement = 'all'")
    assert db.execute("SELECT count(*) FROM duckdb_settings() WHERE name = 'gatekeeper_enforcement'").fetchone() == (0,)
    db.execute("SET lock_configuration = true")
    with db.cursor() as cursor:
        enforce(cursor)
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            cursor.execute("CREATE TABLE u(x INTEGER)")


@pytest.mark.xfail(strict=True, reason="DuckDB 1.5.5 evaluates PRAGMA argument expressions in the statement "
                   "preprocessor before any extension hook runs; see docs/security.md#residuals and issue #46")
def test_pragma_arguments_are_not_evaluated_on_enforced_connections(catalog, agent):
    # Pins a known engine-side gap. When this starts passing (an engine change or a new hook), remove the
    # xfail and the matching residual in the security model.
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute("PRAGMA no_such_pragma(nextval('reporting.seq'))")
    assert catalog.execute("SELECT nextval('reporting.seq')").fetchone() == (1,)


def test_posture_warnings():
    with connect() as loose:
        warnings = enforce(loose.cursor())
        assert any("enable_external_access" in w for w in warnings)
        assert any("lock_configuration" in w for w in warnings)
        assert any("enable_logging('Gatekeeper')" in w for w in warnings)
    with connect() as tight:
        tight.execute("""SET enable_external_access = false; SET autoinstall_known_extensions = false;
                         SET autoload_known_extensions = false; CALL enable_logging('Gatekeeper');
                         SET lock_configuration = true""")
        assert enforce(tight.cursor()) == []
        # With external access off the engine itself refuses readers, before Gatekeeper is consulted.
        with pytest.raises(duckdb.Error):
            tight.execute("SELECT * FROM read_csv('/nonexistent/x.csv')")


def test_concurrent_enforced_connections_never_leak_under_policy_flips(catalog):
    reporting = {"allowed_tables": [{"schema": "reporting", "table": "*"}]}
    secret = {"allowed_tables": [{"schema": "secret", "table": "*"}]}
    stop = threading.Event()
    leaks = []

    def worker():
        with catalog.cursor() as cursor:
            enforce(cursor)
            while not stop.is_set():
                # Denied under both policies: must never succeed regardless of which snapshot is current.
                try:
                    cursor.execute("SELECT * FROM reporting.orders, secret.salaries").fetchall()
                    leaks.append("cross")
                except duckdb.PermissionException:
                    pass
                for sql in ["SELECT count(*) FROM reporting.orders", "SELECT count(*) FROM secret.salaries"]:
                    try:
                        cursor.execute(sql).fetchall()
                    except duckdb.PermissionException:
                        pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(worker) for _ in range(4)]
        for i in range(40):
            configure(catalog, reporting if i % 2 else secret)
        stop.set()
        for future in futures:
            future.result()
    assert leaks == []
