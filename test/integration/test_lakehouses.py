import json
import os
from pathlib import Path
import uuid

import duckdb
import pytest

pytestmark = pytest.mark.skipif(os.getenv("GATEKEEPER_LAKEHOUSE_TESTS") != "1", reason="opt-in local lakehouse tests")
ROOT = Path(__file__).resolve().parents[2]


def validate(db, sql, policy):
    return db.execute("SELECT gatekeeper_validate(?,?)", [sql, json.dumps(policy)]).fetchone()[0]


@pytest.fixture(params=["iceberg", "ducklake"])
def lake(request, tmp_path):
    db = duckdb.connect(config={"allow_unsigned_extensions": "true"})
    db.execute("LOAD '" + str(ROOT / "build/release/extension/gatekeeper/gatekeeper.duckdb_extension") + "'")
    kind = request.param
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
        metadata = str(tmp_path / "metadata.ducklake").replace("'", "''")
        data = str(tmp_path / "data").replace("'", "''")
        db.execute(f"ATTACH 'ducklake:{metadata}' AS lake (DATA_PATH '{data}', DATA_INLINING_ROW_LIMIT 0)")
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
    try:
        yield db, schema, kind
    finally:
        db.close()


def test_allowed_and_denied_tables(lake):
    db, schema, kind = lake
    sql = f"SELECT sum(amount) FROM lake.{schema}.orders"
    policy = {"allowed_catalogs": ["lake"], "allowed_schemas": [schema],
              "allowed_tables": [{"catalog": "lake", "schema": schema, "table": "orders"}],
              "allow_table_functions": False, "blocked_functions": ["read_parquet", "parquet_scan", "iceberg_scan"]}
    result = validate(db, sql, policy)
    assert result["allowed"], (kind, result)
    assert db.execute(sql).fetchone() == (50.0,)
    for changes in [{"allowed_catalogs": ["other"]}, {"allowed_schemas": ["other"]}, {"allowed_tables": []}]:
        denied = validate(db, sql, {**policy, **changes})
        assert not denied["allowed"] and denied["code"] == "forbidden", (kind, denied)
    db.execute(f"USE lake.{schema}")
    assert validate(db, "SELECT * FROM orders", policy)["allowed"]
    assert not validate(db, "SELECT * FROM secret", policy)["allowed"]
    assert not validate(db, "SELECT * FROM orders WHERE EXISTS (SELECT * FROM secret)", policy)["allowed"]
    assert not validate(db, "SELECT * FROM read_parquet('s3://warehouse/untrusted.parquet')", policy)["allowed"]


def test_trusted_view_and_no_writes(lake):
    db, schema, kind = lake
    db.execute(f"CREATE VIEW main.allowed_view AS SELECT * FROM lake.{schema}.orders")
    policy = {"allowed_catalogs": ["lake"], "allowed_schemas": [schema], "allow_table_functions": False}
    assert validate(db, "SELECT * FROM main.allowed_view", policy)["allowed"]
    assert not validate(db, "SELECT * FROM main.allowed_view", {**policy, "allowed_tables": []})["allowed"]
    result = validate(db, f"DELETE FROM lake.{schema}.orders", policy)
    assert result["code"] == "unsupported"
    assert db.execute(f"SELECT count(*) FROM lake.{schema}.orders").fetchone() == (2,)
