"""Only the explicitly reviewed Parquet reader pair shares a permission."""
import pytest

from test_gatekeeper import db
from typed_helpers import configure, validate


@pytest.mark.parametrize("global_name", ["read_parquet", "PARQUET_SCAN"])
@pytest.mark.parametrize("request_name", ["READ_PARQUET", "parquet_scan"])
def test_either_alias_authorizes_both_spellings_and_shorthand(db, tmp_path, global_name, request_name):
    path = str(tmp_path / "data.parquet").replace("'", "''")
    db.execute(f"COPY (SELECT 1 x) TO '{path}' (FORMAT PARQUET)")
    configure(db, {"allowed_functions": [global_name]})
    for source in [f"read_parquet('{path}')", f"parquet_scan('{path}')", f"'{path}'"]:
        result = validate(db, f"SELECT * FROM {source}", {"allowed_functions": [request_name]})
        assert result["allowed"], result


@pytest.mark.parametrize("blocked", ["read_parquet", "PARQUET_SCAN"])
@pytest.mark.parametrize("global_block", [False, True])
def test_either_alias_blocks_both_spellings_and_shorthand_before_io(db, blocked, global_block):
    blocks = {"blocked_functions": [blocked]}
    configure(db, {"allowed_functions": ["read_parquet", "parquet_scan"], **(blocks if global_block else {})})
    request = {"blocked_functions": []} if global_block else blocks
    for source in ["read_parquet('/missing/data.parquet')", "parquet_scan('/missing/data.parquet')",
                   "'/missing/data.parquet'"]:
        result = validate(db, f"SELECT * FROM {source}", request)
        assert result["code"] == "forbidden" and result["error_message"] == "", result
        assert result["violations"][0]["function_name"] == "read_parquet"


@pytest.mark.parametrize("reader,blocked", [("read_parquet", "parquet_scan"), ("parquet_scan", "read_parquet")])
def test_alias_blocks_apply_inside_trusted_expansions(db, tmp_path, reader, blocked):
    path = str(tmp_path / "data.parquet").replace("'", "''")
    db.execute(f"COPY (SELECT 1 x) TO '{path}' (FORMAT PARQUET)")
    db.execute(f"CREATE VIEW v AS SELECT * FROM {reader}('{path}')")
    db.execute(f"CREATE MACRO m() AS TABLE SELECT * FROM {reader}('{path}')")
    configure(db, {"allowed_functions": ["m"]})
    for sql in ["SELECT * FROM v", "SELECT * FROM m()"]:
        assert validate(db, sql)["allowed"]
        assert not validate(db, sql, {"blocked_functions": [blocked]})["allowed"]


@pytest.mark.parametrize("reader,substitute,suffix", [("read_csv", "read_csv_auto", "csv"),
                                                    ("read_json", "read_json_auto", "json")])
def test_other_reader_names_remain_independent(db, reader, substitute, suffix):
    configure(db, {"allowed_functions": [reader]})
    result = validate(db, f"SELECT * FROM '/missing/data.{suffix}'")
    assert result["code"] == "forbidden"
    assert result["violations"][0]["function_name"] == substitute
