-- Loadable smoke, enforced half: an enforced connection, log-only mode, the audit log, and the configuration
-- lock through the host's query hooks, log manager, and DBConfig. Needs two connections to one database.
--
-- Same conventions as loadable.sql (blank-line paragraphs, in-SQL assertions), plus one directive per
-- paragraph naming the connection that runs it and, when the statement must fail, the text its error must
-- contain:
--
--   -- @host
--   -- @agent
--   -- @agent expect error: Gatekeeper denied
--
-- "host" is the connection the driver configures and reads the log from; "agent" is a second connection to
-- the same database that latches itself with gatekeeper_enforce(). A host with one connection cannot run this
-- file (scripts/smoke_cli.sh covers the same ground in separate processes). The agent's statements stay plain
-- SELECTs after a denial: on DuckDB 2.0 a denial at the text boundary leaves the auto-commit transaction open
-- until the next plain statement ends it (test/support/enforcement.py, settle()).

-- @host
CREATE SCHEMA reporting;

-- @host
CREATE TABLE reporting.orders AS SELECT 20.0 AS amount;

-- @host
CREATE TABLE secret AS SELECT 'x' AS token;

-- @host
CALL gatekeeper_configure(allowed_tables := [{'schema': 'reporting', 'table': '*'}]);

-- @host
CALL enable_logging('Gatekeeper');

-- Allowed decisions are DEBUG records.
-- @host
SET logging_level = 'debug';

-- Only `enforced` is read here: on the DuckDB 2.0 alpha, an expression over both columns of this row
-- (`enforced AND warnings IS NOT NULL`) raises an internal error, and `warnings IS NOT NULL` evaluated after
-- `enforced` returns false; see nozzle/duckdb-gatekeeper#102. scripts/smoke_loadable.py reads both as
-- separate columns, which is correct on both engines.
-- @agent
SELECT CASE WHEN NOT coalesce(enforced, false) THEN error('gatekeeper_enforce did not latch') END
FROM gatekeeper_enforce();

-- The engine executes what the policy allows and refuses the rest before it runs, through the host's hooks.
-- @agent
SELECT CASE WHEN NOT coalesce(sum(amount) = 20.0, false) THEN error('allowed read returned the wrong sum') END
FROM reporting.orders;

-- @agent expect error: Gatekeeper denied
SELECT * FROM secret;

-- @agent expect error: Gatekeeper denied
CREATE TABLE u(x INTEGER);

-- @agent expect error: Gatekeeper denied
SET threads = 1;

-- @agent expect error: Gatekeeper denied
CALL disable_logging();

-- @host
SELECT CASE WHEN NOT coalesce(count(*) = 1, false) THEN error('host connection was enforced too') END
FROM secret;

-- Every decision is a record the host reads back: the allowed read, the table denial, and the three non-read
-- statements. Where the three are decided depends on the client's path into the engine (docs/security.md,
-- "Prepare() binds before it is decided"): Query() refuses them at the text boundary as `unsupported`;
-- a client Prepare() on DuckDB 1.5 (the R package's dbExecute) has no text yet and refuses them in the plan
-- pre-screen, recorded at boundary `prepare` as `forbidden` with no statement. Either way there are three.
-- @host
SELECT CASE WHEN NOT coalesce(count(*) FILTER (WHERE mode = 'enforce' AND allowed AND code = 'ok') = 1
                          AND count(*) FILTER (WHERE mode = 'enforce' AND NOT allowed AND code = 'forbidden'
                                               AND boundary = 'authorize') = 1
                          AND count(*) FILTER (WHERE mode = 'enforce' AND NOT allowed
                                               AND (code = 'unsupported' OR boundary = 'prepare')) = 3
                          AND count(*) = 5, false)
            THEN error('audit records: ' || coalesce(list((boundary, allowed, code) ORDER BY timestamp, context_id)::VARCHAR, '[]')) END
FROM duckdb_logs_parsed('Gatekeeper') WHERE event = 'decision';

-- @host
SELECT CASE WHEN NOT coalesce(count(*) = 1 AND bool_and(violations[1].rule = 'table'), false)
            THEN error('denied record for SELECT * FROM secret: ' || coalesce(list(violations[1].rule)::VARCHAR, '[]')) END
FROM duckdb_logs_parsed('Gatekeeper') WHERE NOT allowed AND statement = 'SELECT * FROM secret';

-- Log-only: the same decisions are recorded and nothing is refused; back to enforcing at the next statement.
-- @host
CALL truncate_duckdb_logs();

-- @host
SET gatekeeper_log_only = true;

-- @agent
SELECT count(*) FROM secret;

-- @host
SELECT CASE WHEN NOT coalesce(count(*) = 1 AND bool_and((mode, allowed, code) = ('log_only', false, 'forbidden')), false)
            THEN error('log-only record: ' || coalesce(list((mode, allowed, code))::VARCHAR, '[]')) END
FROM duckdb_logs_parsed('Gatekeeper') WHERE statement = 'SELECT count(*) FROM secret';

-- @host
SET gatekeeper_log_only = false;

-- @agent expect error: Gatekeeper denied
SELECT count(*) FROM secret;

-- Written order: two records can share a wall-clock timestamp, and context ids are allocated in sequence.
-- @host
SELECT CASE WHEN NOT coalesce(list(new_value ORDER BY timestamp, context_id) = ['true', 'false'], false)
            THEN error('setting records: ' || coalesce(list(new_value ORDER BY timestamp, context_id)::VARCHAR, '[]')) END
FROM duckdb_logs_parsed('Gatekeeper') WHERE event = 'log_only_changed';

-- The configuration lock is the host's; nothing after it can change the policy.
-- @host
SET lock_configuration = true;

-- @host expect error: locked
CALL gatekeeper_configure();
