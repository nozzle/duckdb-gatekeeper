"""Trusted definitions are opaque to table policy.

The caller must be authorized to reference the view or table, or to invoke the macro, that its text names.
What such a host-created definition reads is its own: exempt from allowed_tables, blocked_tables and the
internal-object rule, still reported as evidence. What the caller's own text names is the caller's wherever
it binds, so a definition reading the same object does not make the caller's reference to it the
definition's. Function policy already worked this way (0.2.0); this module pins the table side."""
import duckdb
import pytest

from support.audit import decisions, enable
from support.enforcement import DENIED, attempt, settle
from support.artifact import literal
from support.typed_helpers import configure, rule, validate


def tables(*names, schema="main"):
    return [{"schema": schema, "table": name} for name in names]


def objects(result):
    return sorted((o["schema"], o["table"], o["type"]) for o in result["objects"])


@pytest.fixture
def chain(db):
    """A -> B -> C: b is a view over c, nested_b a view over b, m a table macro over x, and scalar macros whose
    subqueries read secret. The macros are allowed by the ceiling; table policy is the request layer's."""
    db.execute("""CREATE TABLE c(id INTEGER); CREATE TABLE secret(id INTEGER); CREATE TABLE x(id INTEGER);
        CREATE TABLE t(id INTEGER);
        CREATE VIEW b AS SELECT id FROM c;
        CREATE VIEW nested_b AS SELECT id FROM b;
        CREATE VIEW v AS SELECT id FROM t;
        CREATE MACRO m() AS TABLE SELECT * FROM x;
        CREATE MACRO secret_count() AS (SELECT count(*) FROM secret);
        CREATE MACRO secret_plus(n := 1) AS (SELECT count(*) FROM secret) + n;
        CREATE MACRO twice_secret() AS secret_count() * 2;
        CREATE MACRO view_count() AS (SELECT count(*) FROM v);
        CREATE MACRO peek(n) AS TABLE SELECT * FROM query_table(n)""")
    configure(db, {"allowed_functions": ["m", "secret_count", "secret_plus", "twice_secret", "view_count", "peek"]})
    return db


@pytest.mark.parametrize("sql, allowed_tables, expected", [
    # The view the caller names must pass; the table behind it is the view's own.
    ("SELECT * FROM b", ["b"], "ok"),
    ("SELECT * FROM b", ["c"], "forbidden"),
    # The caller's own reference to that table is the caller's, in either order.
    ("SELECT * FROM b JOIN c USING (id)", ["b"], "forbidden"),
    ("SELECT * FROM c JOIN b USING (id)", ["b"], "forbidden"),
    ("SELECT * FROM b JOIN c USING (id)", ["b", "c"], "ok"),
    ("SELECT * FROM b WHERE id IN (SELECT id FROM c)", ["b"], "forbidden"),
    # A view over a view: the caller names the outer one, and only that one.
    ("SELECT * FROM nested_b", ["b"], "forbidden"),
    ("SELECT * FROM nested_b", ["nested_b"], "ok"),
    ("SELECT * FROM nested_b, b", ["nested_b"], "forbidden"),
    # A table macro's body is its own; the caller's reference next to it is not.
    ("SELECT * FROM m()", [], "ok"),
    ("SELECT * FROM m(), x", [], "forbidden"),
])
def test_direct_references_are_checked_and_trusted_bodies_are_not(chain, sql, allowed_tables, expected):
    result = validate(chain, sql, {"allowed_tables": tables(*allowed_tables)})
    assert result["code"] == expected, (sql, result)
    if expected == "forbidden":
        assert result["violations"][0]["rule"] == "table", result
        assert result["violations"][0]["table"] in {"c", "nested_b", "b", "x"}, result


def test_evidence_lists_every_object_read(chain):
    result = validate(chain, "SELECT * FROM nested_b", {"allowed_tables": tables("nested_b")})
    assert result["allowed"]
    assert objects(result) == [("main", "b", "view"), ("main", "c", "table"), ("main", "nested_b", "view")]
    # The same identity reached directly and through the view appears once.
    result = validate(chain, "SELECT * FROM b JOIN c USING (id)", {"allowed_tables": tables("b", "c")})
    assert objects(result) == [("main", "b", "view"), ("main", "c", "table")]
    # Denied results carry no evidence, as before.
    assert validate(chain, "SELECT * FROM b JOIN c USING (id)", {"allowed_tables": tables("b")})["objects"] == []


def test_blocks_apply_to_what_the_caller_names(chain):
    blocked_c = {"blocked_tables": tables("c")}
    result = validate(chain, "SELECT * FROM b", blocked_c)
    assert result["allowed"] and ("main", "c", "table") in objects(result), result
    denied = validate(chain, "SELECT * FROM b, c", blocked_c)
    assert denied["code"] == "forbidden" and denied["violations"][0]["message"] == "object is blocked", denied
    assert validate(chain, "SELECT * FROM b", {"blocked_tables": tables("b")})["code"] == "forbidden"
    # Both layers: a ceiling block on c does not reach the view either; a ceiling block on b does.
    configure(chain, {"allowed_functions": ["m"], "blocked_tables": tables("c")})
    assert validate(chain, "SELECT * FROM b")["allowed"]
    assert not validate(chain, "SELECT * FROM c")["allowed"]
    configure(chain, {"allowed_functions": ["m"], "blocked_tables": tables("b")})
    assert not validate(chain, "SELECT * FROM b")["allowed"]
    assert validate(chain, "SELECT * FROM c")["allowed"]


def test_ceiling_and_request_layers_each_authorize_the_callers_references(chain):
    # The ceiling allows the view; the request layer may narrow to nothing, never widen to the table.
    configure(chain, {"allowed_tables": tables("b")})
    assert validate(chain, "SELECT * FROM b")["allowed"]
    assert validate(chain, "SELECT * FROM b", {"allowed_tables": tables("b")})["allowed"]
    assert not validate(chain, "SELECT * FROM b", {"allowed_tables": []})["allowed"]
    assert not validate(chain, "SELECT * FROM c", {"allowed_tables": tables("b", "c")})["allowed"]
    assert not validate(chain, "SELECT * FROM b, c", {"allowed_tables": tables("b", "c")})["allowed"]


def test_scalar_macro_subqueries_read_the_macros_own_objects(chain):
    # A scalar macro body binds in the caller's binder, so the objects its subqueries read are recognized from
    # its definition: the body's, its default arguments', and those of the host macros it calls.
    for sql in ["SELECT secret_count()", "SELECT secret_plus()", "SELECT secret_plus(n := 2)", "SELECT twice_secret()",
                "SELECT secret_count() FROM b", "SELECT view_count()"]:
        result = validate(chain, sql, {"allowed_tables": tables("b")})
        assert result["allowed"], (sql, result)
    assert objects(validate(chain, "SELECT secret_count()", {"allowed_tables": []})) == [("main", "secret", "table")]
    # A definition names a view: the view's body is trusted by origin from there on.
    assert objects(validate(chain, "SELECT view_count()", {"allowed_tables": []})) == [
        ("main", "t", "table"), ("main", "v", "view")]
    # The caller naming the same object is the caller's, query-wide.
    for sql in ["SELECT secret_count() FROM secret", "SELECT secret_count(), (SELECT count(*) FROM secret)",
                "SELECT twice_secret() FROM secret", "SELECT view_count() FROM t"]:
        denied = validate(chain, sql, {"allowed_tables": tables("b")})
        assert denied["code"] == "forbidden" and denied["violations"][0]["rule"] == "table", (sql, denied)
    # An unrelated table sharing nothing with the macro is still the caller's.
    assert not validate(chain, "SELECT secret_count() FROM c", {"allowed_tables": []})["allowed"]


def test_table_macro_arguments_cannot_carry_table_references(chain):
    # Guardrail, not provenance: a table-function argument is a literal or a parameter before anything binds, so
    # no caller-written table reference can reach a table macro's body binder.
    result = validate(chain, "SELECT * FROM m((SELECT 1))", {"allowed_tables": tables("x")})
    assert result["code"] == "forbidden" and result["violations"][0]["rule"] == "bind_time_expression", result
    result = validate(chain, "SELECT * FROM peek((SELECT 'secret'))", {"allowed_tables": []})
    assert result["code"] == "forbidden" and result["violations"][0]["rule"] == "bind_time_expression", result


def test_caller_ctes_stay_the_callers(chain):
    chain.execute("CREATE MACRO consume() AS TABLE SELECT * FROM x")
    configure(chain, {"allowed_functions": ["consume"]})
    # A caller CTE the table macro's body inherits binds in the caller's scope: the table it reads is the caller's.
    denied = validate(chain, "WITH x AS (SELECT * FROM secret) SELECT * FROM consume()", {"allowed_tables": tables("x")})
    assert denied["code"] == "forbidden" and denied["violations"][0]["table"] == "secret", denied
    assert validate(chain, "WITH x AS (SELECT * FROM secret) SELECT * FROM consume()",
                    {"allowed_tables": tables("x", "secret")})["allowed"]
    # A CTE nothing references is never bound, so nothing is read: no lookup, no decision about secret.
    result = validate(chain, "WITH x AS (SELECT * FROM secret) SELECT 1", {"allowed_tables": []})
    assert result["allowed"] and result["objects"] == [], result


def test_a_written_name_is_the_callers_wherever_it_resolves(chain):
    # v reads t. A CTE named t that the caller also reads makes t the caller's: the name resolves to the CTE for
    # the caller and to the table for the view, and a name the caller wrote is checked wherever it binds.
    # Conservative on purpose; renaming the CTE lifts it.
    denied = validate(chain, "WITH t AS (SELECT 1 AS id) SELECT * FROM v CROSS JOIN t", {"allowed_tables": tables("v")})
    assert denied["code"] == "forbidden" and denied["violations"][0]["table"] == "t", denied
    assert validate(chain, "WITH t AS (SELECT 1 AS id) SELECT * FROM v CROSS JOIN t",
                    {"allowed_tables": tables("v", "t")})["allowed"]
    assert validate(chain, "WITH u AS (SELECT 1 AS id) SELECT * FROM v CROSS JOIN u", {"allowed_tables": tables("v")})["allowed"]
    # A declaration nobody reads and an alias are not references.
    assert validate(chain, "WITH t AS (SELECT 1) SELECT * FROM v", {"allowed_tables": tables("v")})["allowed"]
    assert validate(chain, "SELECT * FROM v AS t", {"allowed_tables": tables("v")})["allowed"]
    assert validate(chain, "SELECT t.id FROM v AS t", {"allowed_tables": tables("v")})["allowed"]


def test_dynamic_table_selection_through_a_trusted_macro_is_the_hosts_capability(chain):
    # peek(n) reads query_table(n): the host has delegated table selection to the caller through a capability it
    # created and the policy allows. The caller's own table restrictions do not apply to what it selects; the
    # caller's own query_table stays on the never-bind list.
    result = validate(chain, "SELECT * FROM peek('secret')", {"allowed_tables": [], "blocked_tables": tables("secret")})
    assert result["allowed"] and objects(result) == [("main", "secret", "table")], result
    assert validate(chain, "SELECT * FROM query_table('secret')", {"allowed_tables": []})["code"] == "forbidden"
    # Blocking the capability itself is what withdraws it.
    assert not validate(chain, "SELECT * FROM peek('secret')", {"blocked_functions": ["peek"]})["allowed"]


def test_scalar_macros_carry_trust_into_what_their_table_functions_bind(chain):
    # A scalar macro body binds in the caller's binder, so query_table(n) inside it is recognized by name; the
    # subquery it replaces itself with is the macro's whatever table it selects, exactly as a table macro's is.
    chain.execute("CREATE MACRO scalar_peek(n) AS (SELECT count(*) FROM query_table(n)); "
                  "CREATE MACRO scalar_fixed() AS (SELECT count(*) FROM query_table('secret'))")
    configure(chain, {"allowed_functions": ["scalar_peek", "scalar_fixed", "peek"]})
    denied_secret = {"allowed_tables": [], "blocked_tables": tables("secret")}
    for sql in ["SELECT scalar_peek('secret')", "SELECT scalar_fixed()", "SELECT * FROM peek('secret')"]:
        result = validate(chain, sql, denied_secret)
        assert result["allowed"] and objects(result) == [("main", "secret", "table")], (sql, result)
    # The caller's own reference to the selected table, and the caller's own query_table, are the caller's.
    for sql in ["SELECT scalar_peek('secret') FROM secret", "SELECT scalar_fixed(), (SELECT count(*) FROM secret)"]:
        denied = validate(chain, sql, denied_secret)
        assert denied["code"] == "forbidden" and denied["violations"][0]["table"] == "secret", (sql, denied)
    for sql in ["SELECT * FROM query_table('secret')", "SELECT scalar_peek('secret'), (SELECT count(*) FROM query_table('secret'))"]:
        denied = validate(chain, sql, denied_secret)
        assert denied["code"] == "forbidden" and denied["violations"][0]["function_name"] == "query_table", (sql, denied)
    assert not validate(chain, "SELECT scalar_peek('secret')", {"blocked_functions": ["scalar_peek"]})["allowed"]


def test_scalar_macros_over_internal_views_own_their_readers(db):
    # An internal metadata view a host scalar macro names is the macro's, and so is the never-bind reader behind
    # it, as it already was behind a host view. The same view named by the caller keeps its reader on the
    # caller's never-bind list, whatever table rules the caller holds.
    db.execute("CREATE MACRO metadata_count() AS (SELECT count(*) FROM information_schema.tables); "
               "CREATE VIEW my_tables AS SELECT table_name FROM information_schema.tables")
    configure(db, {"allowed_functions": ["metadata_count"]})
    for sql in ["SELECT metadata_count()", "SELECT * FROM my_tables", "SELECT metadata_count() FROM my_tables"]:
        result = validate(db, sql, {"allowed_tables": tables("my_tables")})
        assert result["allowed"] and any(f["name"] == "duckdb_tables" for f in result["functions"]), (sql, result)
    denied = validate(db, "SELECT metadata_count(), * FROM information_schema.tables", {"allowed_tables": tables("my_tables")})
    assert denied["violations"][0]["rule"] == "internal_object", denied
    denied = validate(db, "SELECT metadata_count(), (SELECT count(*) FROM duckdb_tables())", {"allowed_tables": tables("my_tables")})
    assert denied["violations"][0]["function_name"] == "duckdb_tables", denied


def test_caller_named_metadata_views_keep_their_readers_never_bind(db):
    # Exact table rules for a caller-named internal metadata view are necessary and not sufficient: the reader
    # behind it is the caller's, and never-bind. Tenant introspection goes through a host definition.
    exact = {"allowed_tables": [{"catalog": "system", "schema": "information_schema", "table": "tables"},
                                {"catalog": "system", "schema": "main", "table": "duckdb_tables"}]}
    configure(db, exact)
    for sql in ["SELECT * FROM information_schema.tables", "SELECT * FROM duckdb_tables"]:
        denied = validate(db, sql, exact)
        assert denied["code"] == "forbidden", (sql, denied)
        assert denied["violations"][0]["rule"] == "function" and denied["violations"][0]["function_name"] == "duckdb_tables", (sql, denied)


def test_internal_views_behind_a_host_view_are_the_views_own(db):
    db.execute("CREATE VIEW my_settings AS SELECT name FROM duckdb_settings() WHERE name = 'threads'; "
               "CREATE VIEW my_tables AS SELECT table_name FROM information_schema.tables")
    for sql in ["SELECT * FROM my_settings", "SELECT * FROM my_tables"]:
        result = validate(db, sql, {"allowed_tables": tables("my_settings", "my_tables")})
        assert result["allowed"], (sql, result)
    # The caller's own internal view still needs an exact rule, next to the host view included.
    for sql in ["SELECT * FROM information_schema.tables", "SELECT * FROM my_tables, information_schema.tables"]:
        result = validate(db, sql, {"allowed_tables": tables("my_settings", "my_tables")})
        assert result["violations"][0]["rule"] == "internal_object", (sql, result)


def test_written_names_match_resolved_identities_in_every_spelling(db):
    db.execute("""ATTACH ':memory:' AS lake; CREATE SCHEMA "Reporting"; CREATE SCHEMA lake.reporting; CREATE SCHEMA "a.b";
        CREATE TABLE "Reporting"."Orders"(id INTEGER); CREATE TABLE lake.reporting.orders(id INTEGER);
        CREATE TABLE main.orders(id INTEGER); CREATE TABLE lake.main.orders(id INTEGER);
        CREATE TABLE "a.b"."x.y"(id INTEGER) ;
        CREATE VIEW v AS SELECT * FROM "Reporting"."Orders";
        CREATE VIEW lake_v AS SELECT * FROM lake.reporting.orders;
        CREATE VIEW dotted_v AS SELECT * FROM "a.b"."x.y" """)
    views = tables("v", "lake_v", "dotted_v")
    # Every spelling of the table the view reads makes it the caller's: unqualified, schema-qualified,
    # catalog-qualified (a two-part name DuckDB resolves as catalog.table), fully qualified, any case, quoted.
    for spelling in ["orders", "reporting.orders", "Reporting.ORDERS", '"Reporting"."Orders"', "memory.reporting.orders",
                     '"MEMORY"."Reporting"."Orders"']:
        denied = validate(db, f"SELECT * FROM v, {spelling}", {"allowed_tables": views})
        assert denied["code"] == "forbidden", (spelling, denied)
        assert denied["violations"][0]["table"] in {"Orders", "orders"}, (spelling, denied)
    for spelling in ["lake.reporting.orders", "lake.main.orders", "lake.orders"]:
        denied = validate(db, f"SELECT * FROM lake_v, {spelling}", {"allowed_tables": views})
        assert denied["code"] == "forbidden" and denied["violations"][0]["catalog"] == "lake", (spelling, denied)
    denied = validate(db, 'SELECT * FROM dotted_v, "a.b"."x.y"', {"allowed_tables": views})
    assert denied["code"] == "forbidden" and denied["violations"][0]["table"] == "x.y", denied
    # A name in another schema or catalog is the caller's own reference to that other table, not to the view's.
    allowed_main = {"allowed_tables": views + [{"catalog": "memory", "schema": "main", "table": "orders"}]}
    assert validate(db, "SELECT * FROM v, main.orders", allowed_main)["allowed"]
    assert validate(db, "SELECT * FROM lake_v, main.orders", allowed_main)["allowed"]
    assert not validate(db, "SELECT * FROM lake_v, lake.main.orders", allowed_main)["allowed"]
    # Evidence preserves the catalog's own casing whichever way the caller spelled the view.
    result = validate(db, 'SELECT * FROM "V"', {"allowed_tables": views})
    assert result["allowed"] and objects(result) == [("Reporting", "Orders", "table"), ("main", "v", "view")], result


def test_temp_shadow_tables_are_separate_identities(db):
    db.execute("CREATE TABLE t(id INTEGER); CREATE VIEW v AS SELECT * FROM t; CREATE TEMP TABLE t(id INTEGER)")
    # The view reads memory.main.t (bound at definition); the caller's unqualified t is the temp shadow. Both are
    # named t, so the caller's reference makes both the caller's; the temp one is what it resolves to.
    denied = validate(db, "SELECT * FROM v, t", {"allowed_tables": tables("v")})
    assert denied["code"] == "forbidden" and denied["violations"][0]["catalog"] == "temp", denied
    assert validate(db, "SELECT * FROM v", {"allowed_tables": tables("v")})["allowed"]
    assert validate(db, "SELECT * FROM v, t", {"allowed_tables": tables("v") + [rule("temp", "main", "t"),
                                                                                 rule("memory", "main", "t")]})["allowed"]


def test_attached_catalog_views_are_trusted_definitions(db):
    db.execute("ATTACH ':memory:' AS lake; CREATE TABLE lake.main.orders(id INTEGER); "
               "CREATE VIEW lake.main.recent AS SELECT * FROM lake.main.orders WHERE id > 0")
    recent = [{"catalog": "lake", "schema": "main", "table": "recent"}]
    result = validate(db, "SELECT * FROM lake.main.recent", {"allowed_tables": recent})
    assert result["allowed"] and [(o["catalog"], o["table"], o["type"]) for o in result["objects"]] == [
        ("lake", "orders", "table"), ("lake", "recent", "view")], result
    assert not validate(db, "SELECT * FROM lake.main.orders", {"allowed_tables": recent})["allowed"]
    assert not validate(db, "SELECT * FROM lake.main.recent, lake.main.orders", {"allowed_tables": recent})["allowed"]


def test_enforced_connections_execute_what_the_policy_allows(catalog, agent):
    # reporting.leak is a host view over secret.salaries under a policy that allows reporting.* only.
    assert agent.execute("SELECT * FROM reporting.leak").fetchall() == [("x", 1.0)]
    assert agent.sql("SELECT count(*) FROM reporting.leak").fetchone() == (1,)
    for sql in ["SELECT * FROM secret.salaries", "SELECT * FROM reporting.leak, secret.salaries",
                "SELECT * FROM reporting.leak WHERE who IN (SELECT who FROM secret.salaries)"]:
        assert attempt(agent, sql).kind == "denied", sql
    settle(agent)
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.table("secret.salaries").fetchall()
    settle(agent)
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.sql("SELECT * FROM reporting.leak").join(agent.table("secret.salaries"), "who").fetchall()
    # Parameters: authorized after the engine binds, with the same outcome.
    assert agent.execute("SELECT * FROM reporting.leak WHERE amount > ?", [0]).fetchall() == [("x", 1.0)]
    assert attempt(agent, "SELECT * FROM secret.salaries WHERE amount > ?", [0]).kind == "denied"


def test_prepared_statements_are_decided_when_they_execute(catalog, agent):
    enable(catalog)
    # Prepare() only pre-screens plan structure (on DuckDB 1.5 it binds before any hook and outside any
    # statement, with neither text nor a private bind on record); table policy is decided at each execution's
    # own authorization, under the policy in force then.
    agent.executemany("SELECT * FROM reporting.leak WHERE amount > ?", [[0], [0]])
    assert agent.fetchall() == [("x", 1.0)]
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.executemany("SELECT * FROM secret.salaries WHERE amount > ?", [[0]])
    found = decisions(catalog, "NOT allowed")
    assert [(r["boundary"], r["violations"][0]["rule"]) for r in found] == [("authorize", "table")], found
    assert found[0]["statement"] == "SELECT * FROM secret.salaries WHERE amount > ?"
    # The policy in force at execution decides: the same parameterized statement, with the view withdrawn in
    # between, is refused, and admitted again once the view is allowed again.
    sql = "SELECT * FROM reporting.leak WHERE amount > ?"
    assert agent.execute(sql, [0]).fetchall() == [("x", 1.0)]
    configure(catalog, {"allowed_tables": [{"schema": "reporting", "table": "orders"}]})
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.execute(sql, [0])
    configure(catalog, {"allowed_tables": [{"schema": "reporting", "table": "*"}]})
    assert agent.execute(sql, [0]).fetchall() == [("x", 1.0)]


def test_parameterless_prepared_statements_are_decided_under_the_policy_in_force_when_they_run(catalog, agent):
    """A prepared statement with no parameters (executemany over an empty parameter set: one Prepare(), one
    Execute()) is decided under the policy in force when it runs, on either engine. On DuckDB 2.0 the prepare
    is a statement carrying the text, so a parameterless statement the policy denies is refused already at
    the prepare (its text is authorized at QueryBegin, as any parameterless statement's is); the execution is
    authorized again under the policy in force then. Each executemany here is its own Prepare() and Execute(),
    so the policy changes sit between preparations as much as between executions. A handle held across the
    change is the native probe's (test/native/prepared_handle_probe.cpp, run against each candidate engine
    in CI): the Python package cannot hold one, since executemany materializes its parameter sets before the
    first execution."""
    enable(catalog, "debug")
    sql = "SELECT * FROM reporting.leak"
    agent.executemany(sql, [[]])
    assert agent.fetchall() == [("x", 1.0)]
    configure(catalog, {"allowed_tables": [{"schema": "reporting", "table": "orders"}]})
    with pytest.raises(duckdb.PermissionException, match=DENIED):
        agent.executemany(sql, [[]])
    configure(catalog, {"allowed_tables": [{"schema": "reporting", "table": "*"}]})
    agent.executemany(sql, [[]])
    assert agent.fetchall() == [("x", 1.0)]
    # Every execution, and no prepare, is recorded as allowed; the refusal is recorded once, at authorization.
    found = decisions(catalog, f"statement = {literal(sql)}")
    assert [(r["boundary"], r["allowed"]) for r in found] == [
        ("execution", True), ("authorize", False), ("execution", True)], found


def test_log_only_records_the_same_decisions_and_refuses_nothing(catalog, agent):
    enable(catalog, "debug")
    catalog.execute("SET gatekeeper_log_only = true")
    assert agent.execute("SELECT * FROM reporting.leak").fetchall() == [("x", 1.0)]
    assert agent.execute("SELECT * FROM reporting.leak, secret.salaries").fetchall() == [("x", 1.0, "x", 1.0)]
    found = decisions(catalog, "statement LIKE 'SELECT * FROM reporting.leak%'")
    assert [(r["statement"], r["mode"], r["allowed"], r["boundary"]) for r in found] == [
        ("SELECT * FROM reporting.leak", "log_only", True, "execution"),
        ("SELECT * FROM reporting.leak, secret.salaries", "log_only", False, "authorize")]
    assert found[1]["violations"][0]["table"] == "salaries" and found[1]["objects"] == []
    assert sorted((o["schema"], o["table"]) for o in found[0]["objects"]) == [("reporting", "leak"), ("secret", "salaries")]
