"""Enforced, log-only, and validated reads against real Iceberg and DuckLake catalogs (opt-in, see
scripts/test_lakehouses.py)."""
import os
import uuid

import duckdb
import pytest

from support.artifact import connect, literal
from support.audit import decisions, enable
from support.enforcement import DENIED, enforce
from support.typed_helpers import configure, validate

pytestmark = pytest.mark.skipif(os.getenv("GATEKEEPER_LAKEHOUSE_TESTS") != "1", reason="opt-in local lakehouse tests")
SCAN = {"iceberg": "iceberg_scan", "ducklake": "ducklake_scan"}


@pytest.fixture(params=["iceberg", "ducklake"])
def lake(request, tmp_path):
    # connect() closes the connection if the artifact fails to load; the context manager closes it after that.
    with connect() as db:
        yield from initialize_lake(db, request.param, tmp_path)


def initialize_lake(db, kind, tmp_path):
    if kind == "iceberg":
        import boto3
        s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:19000", aws_access_key_id="gatekeeper-test", aws_secret_access_key="gatekeeper-local-only", region_name="us-east-1")
        if "warehouse" not in {b["Name"] for b in s3.list_buckets()["Buckets"]}:
            s3.create_bucket(Bucket="warehouse")
        db.execute("LOAD httpfs; LOAD iceberg")
        db.execute("""CREATE SECRET test_s3 (TYPE s3, KEY_ID 'gatekeeper-test', SECRET 'gatekeeper-local-only',
            REGION 'us-east-1', ENDPOINT '127.0.0.1:19000', URL_STYLE 'path', USE_SSL false)""")
        db.execute("ATTACH 'warehouse' AS lake (TYPE iceberg, ENDPOINT 'http://127.0.0.1:18181', AUTHORIZATION_TYPE 'none')")
    else:
        db.execute("LOAD ducklake")
        db.execute(f"ATTACH {literal('ducklake:' + str(tmp_path / 'metadata.ducklake'))} AS lake "
                   f"(DATA_PATH {literal(tmp_path / 'data')}, DATA_INLINING_ROW_LIMIT 0)")
    schema = "test_" + uuid.uuid4().hex[:12]
    db.execute(f"CREATE SCHEMA lake.{schema}")
    db.execute(f"CREATE TABLE lake.{schema}.orders(id BIGINT, amount DOUBLE)")
    db.execute(f"INSERT INTO lake.{schema}.orders VALUES (1,20),(2,30)")
    db.execute(f"CREATE TABLE lake.{schema}.secret AS SELECT 999 AS value")
    if kind == "ducklake":
        assert list((tmp_path / "data").rglob("*.parquet")), "DuckLake must exercise actual backing Parquet reads"
    else:
        objects = s3.list_objects_v2(Bucket="warehouse").get("Contents", [])
        assert any(item["Key"].endswith(".parquet") for item in objects), "Iceberg must store backing Parquet data"
    yield db, schema, kind


def test_allowed_and_denied_tables(lake):
    db, schema, kind = lake
    sql = f"SELECT sum(amount) FROM lake.{schema}.orders"
    policy = {"allowed_tables": [{"catalog": "lake", "schema_path": [schema], "table": "orders"}]}
    configure(db, policy)
    result = validate(db, sql, policy)
    assert result["allowed"], (kind, result)
    assert result["caller_objects"] == [{"catalog": "lake", "schema_path": [schema], "table": "orders", "type": "table"}]
    assert db.execute(sql).fetchone() == (50.0,)
    # The scan function an attached catalog resolves an allowed table to is the catalog's, not the caller's: a
    # block on it does not reach the read, and it is still reported in the dependency list. The caller's own
    # call of the same function is another matter, and the never-bind list holds everywhere.
    blocked = validate(db, sql, {**policy, "blocked_functions": [SCAN[kind]]})
    assert blocked["allowed"] and SCAN[kind] in {f["name"] for f in blocked["functions"]}, (kind, blocked)
    if kind == "iceberg":
        direct = validate(db, "SELECT * FROM iceberg_scan('s3://warehouse/untrusted')",
                          {**policy, "allowed_functions": ["iceberg_scan"], "blocked_functions": ["iceberg_scan"]})
        assert direct["code"] == "forbidden" and direct["violations"][0]["function_name"] == "iceberg_scan", direct
    for changes in [{"allowed_tables": [{"catalog": "other", "schema_path": ["*"], "table": "*"}]},
                    {"allowed_tables": [{"catalog": "*", "schema_path": ["other"], "table": "*"}]}, {"allowed_tables": []}]:
        denied = validate(db, sql, {**policy, **changes})
        assert not denied["allowed"] and denied["code"] == "forbidden", (kind, denied)
    db.execute(f"USE lake.{schema}")
    assert validate(db, "SELECT * FROM orders", policy)["allowed"]
    assert not validate(db, "SELECT * FROM secret", policy)["allowed"]
    assert not validate(db, "SELECT * FROM secret", {**policy, "allowed_tables": [
        {"catalog": "lake", "schema_path": [schema], "table": "secret"}]})["allowed"]
    assert not validate(db, "SELECT * FROM orders WHERE EXISTS (SELECT * FROM secret)", policy)["allowed"]
    assert not validate(db, "SELECT * FROM read_parquet('s3://warehouse/untrusted.parquet')", policy)["allowed"]


def test_trusted_view_and_no_writes(lake):
    db, schema, kind = lake
    db.execute(f"CREATE VIEW main.allowed_view AS SELECT * FROM lake.{schema}.orders")
    policy = {"allowed_tables": [{"catalog": "lake", "schema_path": [schema], "table": "*"},
                                 {"catalog": "memory", "schema_path": ["main"], "table": "*"}]}
    assert validate(db, "SELECT * FROM main.allowed_view", policy)["allowed"]
    assert not validate(db, "SELECT * FROM main.allowed_view", {**policy, "allowed_tables": []})["allowed"]
    # The host view is a trusted definition: the lake table it reads is the view's own, still reported as
    # evidence with the identity the attached catalog resolved it to. The caller's own reference to that table,
    # next to the view, is the caller's.
    view_only = {"allowed_tables": [{"catalog": "memory", "schema_path": ["main"], "table": "allowed_view"}]}
    result = validate(db, "SELECT * FROM main.allowed_view", view_only)
    assert result["allowed"], result
    assert result["caller_objects"] == [{"catalog": "memory", "schema_path": ["main"], "table": "allowed_view", "type": "view"}]
    assert {"catalog": "lake", "schema_path": [schema], "table": "orders", "type": "table"} in result["objects"], result
    mixed = validate(db, f"SELECT * FROM main.allowed_view, lake.{schema}.orders", policy)
    assert mixed["allowed"] and mixed["caller_objects"] == [
        {"catalog": "lake", "schema_path": [schema], "table": "orders", "type": "table"},
        {"catalog": "memory", "schema_path": ["main"], "table": "allowed_view", "type": "view"}]
    assert not validate(db, f"SELECT * FROM main.allowed_view, lake.{schema}.orders", view_only)["allowed"]
    assert not validate(db, f"SELECT * FROM lake.{schema}.orders", view_only)["allowed"]
    result = validate(db, f"DELETE FROM lake.{schema}.orders", policy)
    assert result["code"] == "unsupported"
    assert db.execute(f"SELECT count(*) FROM lake.{schema}.orders").fetchone() == (2,)


def test_enforced_connection_reads_allowed_lake_tables_and_refuses_the_rest(lake, tmp_path):
    # The real read path of each lakehouse (catalog resolution, the scan function it resolves to, the backing
    # Parquet) runs through an enforced connection; everything the policy denies is refused before it reaches
    # the lake, with and without parameters.
    db, schema, kind = lake
    policy = {"allowed_tables": [{"catalog": "lake", "schema_path": [schema], "table": "orders"}]}
    configure(db, policy)
    with db.cursor() as agent:
        agent.execute(f"USE lake.{schema}")  # before enforcing: an enforced connection cannot change its search path
        enforce(agent)
        assert agent.execute(f"SELECT sum(amount) FROM lake.{schema}.orders").fetchone() == (50.0,)
        assert agent.execute("SELECT amount FROM orders WHERE id = ?", [2]).fetchone() == (30.0,)
        untrusted = "s3://warehouse/untrusted.parquet" if kind == "iceberg" else str(tmp_path / "untrusted.parquet")
        for sql, parameters in [("SELECT * FROM secret", []), (f"SELECT * FROM lake.{schema}.secret", []),
                                ("SELECT * FROM secret WHERE value = ?", [999]),
                                ("SELECT * FROM orders WHERE EXISTS (SELECT * FROM secret)", []),
                                ("SELECT * FROM orders o WHERE EXISTS (SELECT 1 FROM secret s WHERE s.value = o.id)", []),
                                ("SELECT * FROM read_parquet(?)", [untrusted]),
                                (f"DELETE FROM lake.{schema}.orders", []), ("INSERT INTO orders VALUES (3, 50)", []),
                                (f"USE lake.{schema}", [])]:
            with pytest.raises(duckdb.PermissionException, match=DENIED):
                agent.execute(sql, parameters)
        # A refused statement still executes normally on the same connection afterwards.
        assert agent.execute("SELECT count(*) FROM orders").fetchone() == (2,)
    # Nothing reached the lake, and the host connection is unenforced.
    assert db.execute(f"SELECT count(*) FROM lake.{schema}.orders").fetchone() == (2,)
    assert db.execute(f"SELECT value FROM lake.{schema}.secret").fetchone() == (999,)


def test_host_policy_changes_apply_to_enforced_connections_at_their_next_statement(lake):
    db, schema, kind = lake
    db.execute(f"CREATE VIEW main.allowed_view AS SELECT * FROM lake.{schema}.orders")
    policy = {"allowed_tables": [{"catalog": "lake", "schema_path": [schema], "table": "*"},
                                 {"catalog": "memory", "schema_path": ["main"], "table": "*"}]}
    configure(db, policy)
    sql = f"SELECT sum(amount) FROM lake.{schema}.orders"
    with db.cursor() as agent:
        enforce(agent)
        assert agent.execute(sql).fetchone() == (50.0,)
        assert agent.execute("SELECT count(*) FROM main.allowed_view").fetchone() == (2,)
        # Blocking the scan function the lake resolves to does not reach an allowed table's read: the scan is
        # the attached catalog's, not the caller's. Table policy is what governs the lake.
        configure(db, {**policy, "blocked_functions": [SCAN[kind]]})
        assert agent.execute(sql).fetchone() == (50.0,)
        assert agent.execute(f"SELECT amount FROM lake.{schema}.orders WHERE id = ?", [2]).fetchone() == (30.0,)
        # A trusted view is authorized by its own identity: the lake table it reads is the view's own, so
        # withdrawing the lake from the policy leaves the view readable and refuses the caller's own reads.
        configure(db, {"allowed_tables": [{"catalog": "memory", "schema_path": ["main"], "table": "*"}]})
        assert agent.execute("SELECT count(*) FROM main.allowed_view").fetchone() == (2,)
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql)
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(f"SELECT count(*) FROM main.allowed_view, lake.{schema}.orders")
        configure(db, {"allowed_tables": []})
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute("SELECT count(*) FROM main.allowed_view")
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(sql)
        configure(db, policy)
        assert agent.execute(sql).fetchone() == (50.0,)


def test_log_only_connection_records_lake_decisions_and_refuses_nothing(lake, tmp_path):
    # The adoption path on a real lakehouse: the enforced connection behaves like an unenforced one while every
    # decision is recorded as the gatekeeper_validate row for it, allowed reads naming the lake's scan function.
    db, schema, kind = lake
    policy = {"allowed_tables": [{"catalog": "lake", "schema_path": [schema], "table": "orders"}]}
    configure(db, policy)
    enable(db, "debug")
    db.execute("SET gatekeeper_log_only = true")
    orders, secret = f"SELECT sum(amount) FROM lake.{schema}.orders", f"SELECT value FROM lake.{schema}.secret"
    untrusted = "s3://warehouse/untrusted.parquet" if kind == "iceberg" else str(tmp_path / "untrusted.parquet")
    reader = "SELECT * FROM read_parquet(?)"  # the path travels as a parameter, never as SQL text
    write = f"INSERT INTO lake.{schema}.secret VALUES (1000)"
    with db.cursor() as agent:
        enforce(agent)
        assert agent.execute(orders).fetchone() == (50.0,)
        assert agent.execute(secret).fetchone() == (999,)
        assert agent.execute(f"{secret} WHERE value = ?", [999]).fetchone() == (999,)
        with pytest.raises(duckdb.Error) as failure:  # the engine's own error for a reader over a missing object
            agent.execute(reader, [untrusted])
        assert not DENIED.search(str(failure.value)), failure.value
        agent.execute(write)  # log-only protects nothing: the write reaches the lake
        assert db.execute(f"SELECT count(*) FROM lake.{schema}.secret").fetchone() == (2,)
        found = decisions(db, "mode = 'log_only'")
        assert [(r["statement"], r["allowed"], r["code"], r["log_level"]) for r in found] == [
            (orders, True, "ok", "DEBUG"), (secret, False, "forbidden", "INFO"),
            (f"{secret} WHERE value = ?", False, "forbidden", "INFO"), (reader, False, "forbidden", "INFO"),
            (write, False, "unsupported", "INFO")], found
        for record in found:
            expected = validate(db, record["statement"], policy)
            for column in ["allowed", "code", "violations", "objects", "functions", "caller_objects"]:
                assert record[column] == expected[column], (record["statement"], column, record, expected)
        assert found[0]["objects"] == [{"catalog": "lake", "schema_path": [schema], "table": "orders", "type": "table"}]
        assert SCAN[kind] in {f["name"] for f in found[0]["functions"]}, found[0]
        assert [v["table"] for v in found[1]["violations"]] == ["secret"]
        assert [v["function_name"] for v in found[3]["violations"]] == ["read_parquet"]
        assert decisions(db, "mode = 'enforce'") == []
        # Turning log-only off refuses the same statement on the same connection at its next statement.
        db.execute("SET gatekeeper_log_only = false")
        with pytest.raises(duckdb.PermissionException, match=DENIED):
            agent.execute(secret)
        modes = [r["mode"] for r in decisions(db, f"statement = {literal(secret)} AND mode <> 'validate'")]
        assert modes == ["log_only", "enforce"], modes
