import concurrent.futures
import json

import pytest
import duckdb

from test_gatekeeper import connect, db
from typed_helpers import validate, configure


def test_resolves_unqualified_objects(db):
    db.execute("CREATE SCHEMA reporting; CREATE TABLE reporting.orders(x INT); SET schema='reporting'")
    assert validate(db,"SELECT sum(x) FROM orders",{"allowed_tables":[{"catalog":"*","schema":"reporting","table":"*"}]})["allowed"]
    result=validate(db,"SELECT sum(x) FROM orders",{"allowed_tables":[{"catalog":"*","schema":"secret","table":"*"}]})
    assert result["code"]=="forbidden"
    assert validate(db,"SELECT * FROM orders",{"allowed_tables":[{"schema":"reporting","table":"orders"}]})["allowed"]
    assert not validate(db,"SELECT * FROM orders",{"allowed_tables":[]})["allowed"]
    assert validate(db,"SELECT * FROM orders",{"allowed_tables":[{"catalog":"memory","schema":"*","table":"*"}]})["allowed"]


def test_binding_errors_and_no_execution(db):
    result=validate(db,"SELECT * FROM missing")
    assert not result["allowed"] and result["code"]=="binding"
    with pytest.raises(duckdb.BinderException, match="Invalid named parameter"):
        validate(db,"SELECT * FROM missing",{"resolve_objects":False})
    db.execute("CREATE TABLE t(x INT); CREATE SEQUENCE seq")
    assert not validate(db,"SELECT nextval('seq')",{"allowed_functions":["nextval"]})["allowed"]
    assert db.execute("SELECT nextval('seq')").fetchone()==(1,)


def test_trusted_views_and_macros(db):
    configure(db, {"allowed_functions": ["report"]})
    db.execute("CREATE SCHEMA reporting; CREATE SCHEMA secret; CREATE TABLE secret.t(x INT); CREATE VIEW reporting.v AS SELECT * FROM secret.t; CREATE MACRO report() AS TABLE SELECT * FROM secret.t")
    reporting = {"catalog": "*", "schema": "reporting", "table": "*"}
    secret = {"catalog": "*", "schema": "secret", "table": "*"}
    assert not validate(db,"SELECT * FROM reporting.v",{"allowed_tables":[reporting]})["allowed"]
    assert validate(db,"SELECT * FROM reporting.v",{"allowed_tables":[reporting,secret]})["allowed"]
    assert not validate(db,"SELECT * FROM report()",{"allowed_functions":["report"],"allowed_tables":[reporting]})["allowed"]
    assert validate(db,"SELECT * FROM report()",{"allowed_functions":["report"],"allowed_tables":[secret]})["allowed"]


def test_attached_database_and_trusted_reader(db,tmp_path):
    db.execute("ATTACH ':memory:' AS lake; CREATE TABLE lake.main.orders AS SELECT 1 AS x")
    options={"allowed_tables":[{"catalog":"lake","schema":"main","table":"orders"}]}
    assert validate(db,"SELECT * FROM lake.main.orders",options)["allowed"]
    assert not validate(db,"SELECT * FROM lake.main.orders",{**options,"allowed_tables":[{"catalog":"other","schema":"*","table":"*"}]})["allowed"]
    path=str(tmp_path/'trusted.parquet').replace("'","''")
    db.execute(f"COPY lake.main.orders TO '{path}' (FORMAT PARQUET)")
    db.execute(f"CREATE VIEW lake.main.file_view AS SELECT * FROM read_parquet('{path}')")
    options = {"allowed_tables": [{"catalog": "lake", "schema": "*", "table": "*"}]}
    assert validate(db,"SELECT * FROM lake.main.file_view",options)["allowed"]
    assert not validate(db,"SELECT * FROM lake.main.file_view",{**options,"blocked_functions":["read_parquet"]})["allowed"]
    assert not validate(db,f"SELECT * FROM read_parquet('{path}')",{"blocked_functions":["read_parquet"]})["allowed"]


def test_ceiling_shared_and_replacement_is_global(db):
    configure(db,{"blocked_functions":["md5"],"max_statements":2})
    with db.cursor() as other:
        assert not validate(other,"SELECT md5('x')")["allowed"]
        assert not validate(other,"SELECT md5('x')",{"blocked_functions":[]})["allowed"]
        assert validate(other,"SELECT 1;SELECT 2")["allowed"]
        assert validate(other,"SELECT 1;SELECT 2",{"use_default_functions":False})["allowed"]
        configure(other)
        assert validate(db,"SELECT md5('x')")["allowed"]
    with connect() as independent:
        assert validate(independent,"SELECT md5('x')")["allowed"]


def test_invalid_configuration_does_not_lock(db):
    with pytest.raises(duckdb.Error):
        configure(db,{"unknown":True})
    assert configure(db) is True
    assert configure(db) is True


def test_prepared_validation_observes_defaults(db):
    db.execute("PREPARE v AS SELECT allowed FROM gatekeeper_validate('SELECT md5(''x'')')")
    assert db.execute("EXECUTE v").fetchone()[0]
    configure(db,{"blocked_functions":["md5"]})
    assert not db.execute("EXECUTE v").fetchone()[0]


def test_configuration_race(db):
    def attempt(i):
        with db.cursor() as conn:
            try:
                configure(conn,{"allowed_functions":[f"custom_{i}"]})
                return True
            except duckdb.Error:
                return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt,range(8)))==8
    policy = db.execute("SELECT current_setting('gatekeeper_policy')").fetchone()[0]
    assert policy["allowed_functions"] in [[f"custom_{i}"] for i in range(8)]


def test_binding_preserves_temp_and_transaction_context(db):
    db.execute("CREATE TEMP TABLE temp_t(x INT); BEGIN; CREATE TABLE uncommitted(x INT)")
    assert validate(db,"SELECT * FROM temp_t")["allowed"]
    assert validate(db,"SELECT * FROM uncommitted")["allowed"]
    db.execute("ROLLBACK")
    assert validate(db,"SELECT * FROM uncommitted")["code"]=="binding"


def test_show_policy_is_preserved(db):
    db.execute("CREATE TABLE t(x INT)")
    assert not validate(db,"SHOW TABLES",{"allowed_tables":[]})["allowed"]
    assert not validate(db,"SHOW ALL TABLES",{"allowed_tables":[{"catalog":"*","schema":"main","table":"*"}]})["allowed"]
    result = validate(db,"SHOW TABLES FROM main",{"allowed_tables":[{"catalog":"*","schema":"main","table":"*"}]})
    assert result["code"] == "forbidden"
    assert "table" in {v["rule"] for v in result["violations"]}


def test_bound_cte_and_policy_override(db):
    db.execute("CREATE TABLE secret(x INT)")
    sql="SELECT * FROM secret WHERE EXISTS (WITH secret AS (SELECT 1) SELECT * FROM secret)"
    assert not validate(db,sql,{"allowed_tables":[]})["allowed"]
    configure(db,{"allowed_tables":[],"allowed_functions":["custom"]})
    assert not validate(db,"SELECT * FROM secret",{"allowed_tables":[{"schema":"main","table":"secret"}]})["allowed"]
    assert validate(db,"SELECT mystery(1)",{"allowed_functions":["mystery"]})["code"]=="forbidden"
