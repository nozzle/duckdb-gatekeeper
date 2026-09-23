"""The reporting/secret catalog the parity legs share, and the statements they decide against it.

Three legs read this corpus: test_enforcement asserts the engine refuses what gatekeeper_validate denies,
test_audit asserts the record says what gatekeeper_validate says and what the agent saw, and test_log_only
asserts a log-only connection behaves like an unenforced one while recording the gatekeeper_validate row.
Each keeps its own assertions; only the statements and the catalog are shared."""
import atexit
from pathlib import Path
import shutil
import tempfile

# Where the corpus's writing statements point. Enforced connections refuse them, but the log-only leg runs
# every statement for real on a log-only and on a plain connection, so the paths must be this process's own:
# two suites sharing a fixed path would overwrite each other's files mid-run. Removed when the interpreter
# exits.
SCRATCH = Path(tempfile.mkdtemp(prefix="gatekeeper-tests-"))
atexit.register(shutil.rmtree, SCRATCH, ignore_errors=True)


def scratch(name):
    """``name`` as a SQL string literal path under this process's scratch directory."""
    return "'" + str(SCRATCH / name).replace("'", "''") + "'"


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

# Statement text the three legs decide against CATALOG_POLICY, each comparing its own observation with what
# gatekeeper_validate says about it. Allowed rows read only reporting.* under the fixture policy.
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
    "SELECT list_transform([1, 2], lambda x: x + 1)",
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
    f"COPY reporting.orders TO {scratch('enforcement_test.csv')}",
    f"EXPORT DATABASE {scratch('enforcement_export')}",
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
