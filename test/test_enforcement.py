"""Enforced connections: the engine refuses what gatekeeper_validate would deny, without host glue."""
import concurrent.futures
import threading

import duckdb
import pytest

from support.artifact import connect, literal
from support.corpus import CATALOG_POLICY, PARITY_CORPUS
from support.enforcement import DENIED, attempt, enforce
from support.typed_helpers import configure, validate


@pytest.mark.parametrize("sql", PARITY_CORPUS)
def test_enforcement_agrees_with_validate(catalog, agent, sql):
    # First leg of the parity oracle: what gatekeeper_validate denies, the enforced connection refuses as a
    # Gatekeeper denial; what the engine cannot bind fails in the engine's own words on both.
    expected = validate(catalog, sql)
    seen = attempt(agent, sql)
    if seen.kind == "rows":
        assert expected["allowed"], (sql, expected)
        return
    # Validation binds but never executes, so an allowed statement may still fail at runtime
    # (a bad cast, for instance). What it must never do is trip a Gatekeeper denial.
    assert not expected["allowed"] or seen.kind == "engine", (sql, seen.error)
    if expected["code"] in {"forbidden", "unsupported"}:
        assert seen.kind == "denied" and isinstance(seen.error, duckdb.PermissionException), (sql, seen.error)
    elif not expected["allowed"]:
        assert expected["code"] in {"binding", "parser"} and seen.kind == "engine", (sql, expected, seen.error)


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
    # Temporary types are connection-local, and validate ran on the catalog connection: an enum it created would
    # be visible here and nowhere else. The agent then creates its own, in its own session.
    assert catalog.execute("SELECT count(*) FROM duckdb_types() WHERE type_name LIKE '__pivot_enum_%'").fetchone()[0] == 0
    assert agent.execute(sql).fetchall() == catalog.execute(static).fetchall()
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


def test_denied_statements_have_no_effect(catalog, agent, tmp_path):
    path = tmp_path / "no_effect.csv"
    before = catalog.execute("SELECT count(*) FROM duckdb_tables()").fetchone()[0]
    for sql in ["CREATE TABLE u AS SELECT * FROM reporting.orders",
                f"COPY reporting.orders TO {literal(path)}",
                "INSERT INTO reporting.orders VALUES (9, 1.0, 'z')",
                "CREATE TEMP TABLE tmp(x INTEGER)"]:
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql)
    assert catalog.execute("SELECT count(*) FROM duckdb_tables()").fetchone()[0] == before
    assert catalog.execute("SELECT count(*) FROM reporting.orders").fetchone()[0] == 3
    assert not path.exists()


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
    # md5 is blocked by name, but the view's md5 is the view's: allowed on both paths, and reported...
    expected = validate(catalog, "SELECT * FROM reporting.hashed")
    assert expected["allowed"] and any(f["name"] == "md5" for f in expected["functions"]), expected
    assert len(agent.execute("SELECT * FROM reporting.hashed").fetchall()) == 3
    # ...while the caller's own md5 stays blocked, alone or next to the view, on both paths...
    for sql in ["SELECT md5(tag) FROM reporting.orders", "SELECT md5(h) FROM reporting.hashed"]:
        assert validate(catalog, sql)["code"] == "forbidden", sql
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql).fetchall()
    # ...and the trusted boundary is absolute: a view over a never-bind function is the host's decision to
    # expose it, allowed when the view is, on both paths. Only Gatekeeper's own control plane stays refused on
    # every route: a view over it would let a SELECT rewrite the policy or erase the audit trail.
    catalog.execute("CREATE VIEW reporting.settings_count AS SELECT count(*) AS n FROM duckdb_settings()")
    assert validate(catalog, "SELECT * FROM reporting.settings_count")["allowed"]
    assert agent.execute("SELECT * FROM reporting.settings_count").fetchone()[0] > 0
    for body in ["gatekeeper_configure()", "truncate_duckdb_logs()", "enable_logging('Gatekeeper')"]:
        catalog.execute(f"CREATE VIEW reporting.control AS SELECT * FROM {body}")
        result = validate(catalog, "SELECT * FROM reporting.control")
        assert result["code"] == "forbidden" and result["violations"][0]["rule"] == "function", (body, result)
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute("SELECT * FROM reporting.control").fetchall()
        catalog.execute("DROP VIEW reporting.control")
    catalog.execute("CREATE VIEW reporting.version AS SELECT * FROM pragma_version()")
    expected = validate(catalog, "SELECT library_version FROM reporting.version")
    if expected["allowed"]:
        assert agent.execute("SELECT library_version FROM reporting.version").fetchall()
    else:
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute("SELECT library_version FROM reporting.version").fetchall()


def test_blocks_reach_caller_implementations_but_not_view_bodies_on_enforced_connections(catalog, agent):
    # The implementation DuckDB binds for the caller's own expression (the aggregate list_sum dispatches, the
    # collation's lower) is the caller's on an enforced connection too, including when it is bound in a child
    # binder created after a trusted view in the same statement, and including parameterized statements. The
    # same implementation inside the view is the view's.
    catalog.execute("CREATE VIEW reporting.sums AS SELECT list_sum([amount]) AS s, tag FROM reporting.orders")
    catalog.execute("CREATE VIEW reporting.folded AS SELECT tag FROM reporting.orders WHERE tag COLLATE nocase = 'A'")
    configure(catalog, {**CATALOG_POLICY, "blocked_functions": ["sum", "lower"]})
    for sql in ["SELECT s FROM reporting.sums", "SELECT tag FROM reporting.folded",
                "SELECT s FROM reporting.sums WHERE tag = ?"]:
        assert validate(catalog, sql.replace("?", "'a'"))["allowed"], sql
        assert agent.execute(sql, ["a"] if "?" in sql else None).fetchall()
    for sql in ["SELECT list_sum([amount]) FROM reporting.orders",
                "SELECT (SELECT list_sum([1])) FROM reporting.sums",
                "SELECT * FROM reporting.sums, (SELECT list_sum([1]) AS q)",
                "SELECT tag FROM reporting.folded WHERE tag COLLATE nocase = 'B'",
                "SELECT list_sum([?]) FROM reporting.sums"]:
        assert validate(catalog, sql.replace("?", "1"))["code"] == "forbidden", sql
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql, [1] if "?" in sql else None).fetchall()


def test_file_shorthand_inside_trusted_views_is_enforced_like_the_reader_call(catalog, agent, tmp_path):
    # FROM 'file' in a host view is that view's reader, outside function policy like an explicit call there, on
    # an enforced connection exactly as gatekeeper_validate decides it. The engine's own bind reaches the
    # replacement gate outside the private bind, parameterized statements reach it before the private bind
    # runs, and neither may treat the view's name as one the caller wrote.
    path = str(tmp_path / "trusted.parquet").replace("'", "''")
    catalog.execute(f"COPY (SELECT 1 AS x UNION ALL SELECT 2) TO '{path}' (FORMAT PARQUET)")
    catalog.execute(f"CREATE VIEW reporting.by_path AS SELECT * FROM '{path}'")
    catalog.execute(f"CREATE VIEW reporting.by_call AS SELECT * FROM read_parquet('{path}')")
    for view in ["reporting.by_path", "reporting.by_call"]:
        assert validate(catalog, f"SELECT * FROM {view}")["allowed"]
        assert agent.execute(f"SELECT sum(x) FROM {view}").fetchone() == (3,)
        assert agent.execute(f"SELECT x FROM {view} WHERE x > ?", [1]).fetchall() == [(2,)]
    # The caller's own spelling of the same file is the caller's reader choice and stays denied, alone or
    # alongside the trusted view.
    for sql in [f"FROM '{path}'", f"SELECT * FROM read_parquet('{path}')",
                f"SELECT * FROM reporting.by_path, '{path}'", f"SELECT * FROM reporting.by_path WHERE x IN (SELECT x FROM '{path}')"]:
        assert validate(catalog, sql)["code"] == "forbidden", sql
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql).fetchall()
    # A block on the reader does not reach into either body, on either path, with or without parameters.
    configure(catalog, {**CATALOG_POLICY, "blocked_functions": ["parquet_scan"]})
    for view in ["reporting.by_path", "reporting.by_call"]:
        assert validate(catalog, f"SELECT * FROM {view}")["allowed"]
        assert agent.execute(f"SELECT sum(x) FROM {view}").fetchone() == (3,)
        assert agent.execute(f"SELECT x FROM {view} WHERE x > ?", [0]).fetchall() == [(1,), (2,)]
    # Prepare() (executemany) binds before any hook and outside any statement, so no text is on record and the
    # gate pre-screens every replacement as caller-written: the shorthand view is refused at prepare time, the
    # explicit-call view is not. The one entry point where the two spellings differ; execute() above does not.
    configure(catalog, CATALOG_POLICY)
    agent.executemany("SELECT x FROM reporting.by_call WHERE x > ?", [[1]])
    assert agent.fetchall() == [(2,)]
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.executemany("SELECT x FROM reporting.by_path WHERE x > ?", [[1]])


def test_explain_and_prepare_of_enforce_do_not_latch(db):
    db.execute("EXPLAIN SELECT * FROM gatekeeper_enforce()").fetchall()
    db.execute("PREPARE latch AS SELECT * FROM gatekeeper_enforce()")
    db.execute("CREATE TABLE still_host(x INTEGER)")
    db.execute("EXECUTE latch").fetchall()
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        db.execute("CREATE TABLE now_enforced(x INTEGER)")


def test_enforce_is_refused_inside_an_open_transaction(catalog):
    # An enforced connection cannot COMMIT or ROLLBACK (neither is a read statement), so a latch taken inside a
    # transaction the host opened would strand the connection in a transaction nothing can end. The refusal is a
    # Permission Error, which DuckDB does not treat as invalidating the transaction: the host's transaction stays
    # usable, the connection stays unenforced, and enforcing after COMMIT or ROLLBACK works as before. Python's
    # begin() is a BEGIN TRANSACTION statement and is refused the same way.
    for end in ["COMMIT", "ROLLBACK"]:
        with catalog.cursor() as cursor:
            cursor.execute("BEGIN TRANSACTION")
            with pytest.raises(duckdb.PermissionException, match="cannot run inside an open transaction"):
                cursor.execute("CALL gatekeeper_enforce()")
            assert cursor.execute("SELECT count(*) FROM secret.salaries").fetchone() == (1,)
            cursor.execute(end)
            assert cursor.execute("SELECT enforced FROM gatekeeper_enforce()").fetchone() == (True,)
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                cursor.execute("SELECT * FROM secret.salaries")
    with catalog.cursor() as cursor:
        cursor.begin()
        with pytest.raises(duckdb.PermissionException, match="cannot run inside an open transaction"):
            cursor.execute("CALL gatekeeper_enforce()")
        cursor.rollback()
    # EXPLAIN and PREPARE inside the transaction are bind-only and unaffected; EXECUTE is the refused execution.
    with catalog.cursor() as cursor:
        cursor.execute("BEGIN TRANSACTION")
        cursor.execute("EXPLAIN SELECT * FROM gatekeeper_enforce()").fetchall()
        cursor.execute("PREPARE latch AS SELECT * FROM gatekeeper_enforce()")
        with pytest.raises(duckdb.PermissionException, match="cannot run inside an open transaction"):
            cursor.execute("EXECUTE latch")
        cursor.execute("ROLLBACK")
        assert cursor.execute("EXECUTE latch").fetchone()[0] is True


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


@pytest.mark.xfail(strict=True, reason="the engine evaluates PRAGMA argument expressions in the statement "
                   "preprocessor before any extension hook runs (nozzle/duckdb-gatekeeper#46)")
def test_pragma_arguments_are_not_evaluated_on_enforced_connections(catalog, agent):
    # Pins a known engine-side gap; strict, so an engine repin that closes it fails here. When this starts
    # passing (an engine change or a new hook), remove the xfail and the matching residual in
    # docs/security.md#residuals.
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
