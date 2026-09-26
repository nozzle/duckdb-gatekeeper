-- Loadable smoke, portable half: checks that cross the host/loadable ABI boundary and need one connection.
--
-- Every host that ships an artifact runs this file against it: the pinned Python package
-- (scripts/smoke_loadable.py, and test/test_smoke_sql.py on the local build), the official DuckDB CLI for
-- the musl targets (scripts/smoke_cli.sh), and the CRAN duckdb package for the MinGW target
-- (scripts/smoke_loadable.R). The file is kept plain so each of those can run it without a parser of its own:
--
--   - statements are separated by blank lines and end with a semicolon; the CLI reads the file as is, the
--     other drivers split on blank lines, drop comment lines, and execute each paragraph;
--   - every check asserts inside SQL: a CASE that calls error() when the condition fails (the false branch is
--     never evaluated), wrapped in coalesce so a NULL condition fails too. A driver only has to require that
--     every statement succeeds;
--   - the driver loads the artifact first and runs the file from a scratch directory, where the
--     replacement-scan check writes gatekeeper_smoke.parquet.
--
-- The enforced-connection half, which needs a second connection, is enforced.sql.

SELECT CASE WHEN count(*) <> 1 THEN error('gatekeeper is not loaded') END
FROM duckdb_extensions() WHERE extension_name = 'gatekeeper' AND loaded;

CREATE TABLE t(x INTEGER, s VARCHAR);

CREATE VIEW lambda_view AS SELECT list_transform(['a'], lambda v: v COLLATE nocase = 'A') AS l;

CREATE VIEW nested_lambda AS
SELECT list_transform([['a']], lambda xs: list_filter(xs, lambda v: v COLLATE nocase = 'A')) AS l;

CREATE VIEW dispatched AS SELECT list_aggregate([1, 2], 'sum') AS s;

CREATE VIEW unnested AS SELECT unnest([1, 2]) AS u;

-- Lambda bodies inside trusted definitions are reached through the host-created bind data: the collation's
-- lower is observed there and is the view's own, while the same lambda written by the caller is blockable.
SELECT CASE WHEN NOT coalesce(allowed AND list_contains(list_transform(functions, lambda f: f.name), 'lower'), false)
            THEN error('lambda_view: lambda body implementation not observed: ' || code) END
FROM gatekeeper_validate('SELECT * FROM lambda_view');

SELECT CASE WHEN NOT coalesce(allowed, false)
            THEN error('lambda_view: block reached the view''s own lambda body: ' || code) END
FROM gatekeeper_validate('SELECT * FROM lambda_view', blocked_functions := [{schema_path:['*'],name:'lower'}]);

SELECT CASE WHEN NOT coalesce(code = 'forbidden' AND (violations[1].function_name = 'lower' OR violations[1].rule = 'bind_time_expression'), false)
            THEN error('lambda_view: block did not reach the caller''s lambda body: ' || code) END
FROM gatekeeper_validate('SELECT list_transform([''a''], lambda v: v COLLATE nocase = ''A'')',
                         blocked_functions := [{schema_path:['*'],name:'lower'}]);

SELECT CASE WHEN NOT coalesce(allowed AND list_contains(list_transform(functions, lambda f: f.name), 'lower'), false)
            THEN error('nested_lambda: lambda body implementation not observed: ' || code) END
FROM gatekeeper_validate('SELECT * FROM nested_lambda');

SELECT CASE WHEN NOT coalesce(allowed, false)
            THEN error('nested_lambda: block reached the view''s own lambda body: ' || code) END
FROM gatekeeper_validate('SELECT * FROM nested_lambda', blocked_functions := [{schema_path:['*'],name:'lower'}]);

SELECT CASE WHEN NOT coalesce(code = 'forbidden' AND (violations[1].function_name = 'lower' OR violations[1].rule = 'bind_time_expression'), false)
            THEN error('nested_lambda: block did not reach the caller''s lambda body: ' || code) END
FROM gatekeeper_validate('SELECT list_transform([[''a'']], lambda xs: list_filter(xs, lambda v: v COLLATE nocase = ''A''))',
                         blocked_functions := [{schema_path:['*'],name:'lower'}]);

-- The dispatched aggregate is recovered through the serialization callback of the host's function.
SELECT CASE WHEN NOT coalesce(allowed AND list_contains(list_transform(functions, lambda f: f.name || ':' || f.type), 'sum:aggregate'), false)
            THEN error('dispatched aggregate not observed: ' || code) END
FROM gatekeeper_validate('SELECT * FROM dispatched');

SELECT CASE WHEN NOT coalesce(allowed, false)
            THEN error('block reached the view''s own dispatched aggregate: ' || code) END
FROM gatekeeper_validate('SELECT * FROM dispatched', blocked_functions := [{schema_path:['*'],name:'sum'}]);

CALL gatekeeper_configure(allowed_functions := [{'catalog':'system','schema_path':['main'],'name':'list_aggregate'}]);

SELECT CASE WHEN NOT coalesce(code = 'forbidden' AND violations[1].function_name = 'sum', false)
            THEN error('block did not reach the caller''s dispatched aggregate: ' || code) END
FROM gatekeeper_validate('SELECT list_aggregate([1, 2], ''sum'')', blocked_functions := [{schema_path:['*'],name:'sum'}]);

CALL gatekeeper_configure(use_default_functions := false, allowed_functions := [{'catalog':'system','schema_path':['main'],'name':'list_aggregate'}, {'catalog':'system','schema_path':['main'],'name':'list_value'}]);

SELECT CASE WHEN NOT coalesce(code = 'forbidden' AND violations[1].function_name = 'sum', false)
            THEN error('caller-written dispatch target escaped the allowlist: ' || code) END
FROM gatekeeper_validate('SELECT list_aggregate([1, 2], ''sum'')');

RESET gatekeeper_policy;

SELECT CASE WHEN NOT coalesce(allowed AND list_contains(list_transform(functions, lambda f: f.name), 'unnest'), false)
            THEN error('block reached unnest inside a view, or unnest not observed: ' || code) END
FROM gatekeeper_validate('SELECT * FROM unnested', blocked_functions := [{schema_path:['*'],name:'unnest'}]);

SELECT CASE WHEN NOT coalesce(code = 'forbidden', false)
            THEN error('block did not reach the caller''s unnest: ' || code) END
FROM gatekeeper_validate('SELECT unnest([1, 2])', blocked_functions := [{schema_path:['*'],name:'unnest'}]);

-- Replacement scans are decided in Gatekeeper's callback before the host's reader binds.
COPY (SELECT 1 AS x) TO 'gatekeeper_smoke.parquet';

SELECT CASE WHEN NOT coalesce(code = 'forbidden' AND violations[1].function_name = 'read_parquet', false)
            THEN error('replacement scan admitted without a reader grant: ' || code) END
FROM gatekeeper_validate('SELECT * FROM ''gatekeeper_smoke.parquet''');

CALL gatekeeper_configure(allowed_functions := [{'catalog':'system','schema_path':['main'],'name':'read_parquet'}]);

SELECT CASE WHEN NOT coalesce(allowed AND objects[1].type = 'replacement', false)
            THEN error('granted replacement scan not recorded: ' || code) END
FROM gatekeeper_validate('SELECT * FROM ''gatekeeper_smoke.parquet''');

RESET gatekeeper_policy;

-- The policy setting round-trips through the host's DBConfig and prepared executions re-read it.
PREPARE smoke_prepared AS
SELECT CASE WHEN allowed IS DISTINCT FROM $1::BOOLEAN
            THEN error('prepared validation: allowed = ' || allowed::VARCHAR || ', expected ' || $1::VARCHAR) END
FROM gatekeeper_validate('SELECT md5(s) FROM t');

EXECUTE smoke_prepared(true);

CALL gatekeeper_configure(blocked_functions := [{catalog:'system',schema_path:['main'],name:'md5',type:'scalar'}]);

EXECUTE smoke_prepared(false);

SELECT CASE WHEN NOT coalesce(current_setting('gatekeeper_policy').blocked_functions = [{catalog:'system',schema_path:['main'],name:'md5',type:'scalar'}], false)
            THEN error('policy readback disagrees with the configured value') END;

DEALLOCATE smoke_prepared;

RESET gatekeeper_policy;
