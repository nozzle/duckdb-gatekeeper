"""Parquet entry names are exact; shorthand selects parquet_scan on both engines."""
import pytest

from support.typed_helpers import configure, validate


@pytest.mark.parametrize("global_name", ["read_parquet", "PARQUET_SCAN"])
@pytest.mark.parametrize("request_name", ["READ_PARQUET", "parquet_scan"])
def test_alias_grants_are_independent_in_both_layers(db, tmp_path, global_name, request_name):
    path = str(tmp_path / "data.parquet").replace("'", "''")
    db.execute(f"COPY (SELECT 1 x) TO '{path}' (FORMAT PARQUET)")
    configure(db, {"allowed_functions": [{"schema_path": ["main"], "name": global_name}]})
    for source, entry in [(f"read_parquet('{path}')", "read_parquet"),
                          (f"parquet_scan('{path}')", "parquet_scan"), (f"'{path}'", "parquet_scan")]:
        result = validate(db, f"SELECT * FROM {source}", {"allowed_functions": [{"schema_path": ["main"], "name": request_name}]})
        assert result["allowed"] is (global_name.lower() == request_name.lower() == entry), result


@pytest.mark.parametrize("blocked", ["read_parquet", "PARQUET_SCAN"])
@pytest.mark.parametrize("global_block", [False, True])
def test_exact_alias_blocks_and_shorthand_before_io(db, blocked, global_block):
    blocks = {"blocked_functions": [{"schema_path":["*"],"name":blocked}]}
    configure(db, {"allowed_functions": [{"schema_path": ["main"], "name": n} for n in ["read_parquet", "parquet_scan"]], **(blocks if global_block else {})})
    request = {"blocked_functions": []} if global_block else blocks
    for source, entry in [("read_parquet('/missing/data.parquet')", "read_parquet"),
                          ("parquet_scan('/missing/data.parquet')", "parquet_scan"),
                          ("'/missing/data.parquet'", "parquet_scan")]:
        result = validate(db, f"SELECT * FROM {source}", request)
        if blocked.lower() == entry:
            assert result["code"] == "forbidden" and result["error_message"] == "", result
            assert result["violations"][0]["function_name"] == entry
        else:
            assert result["code"] == "binding", result


@pytest.mark.parametrize("reader,blocked", [("read_parquet", "parquet_scan"), ("parquet_scan", "read_parquet")])
def test_alias_blocks_do_not_reach_inside_trusted_expansions(db, tmp_path, reader, blocked):
    # A host view or table macro owns its reader under either alias; the matching
    # block still reaches the caller's own call next to it.
    path = str(tmp_path / "data.parquet").replace("'", "''")
    db.execute(f"COPY (SELECT 1 x) TO '{path}' (FORMAT PARQUET)")
    db.execute(f"CREATE VIEW v AS SELECT * FROM {reader}('{path}')")
    db.execute(f"CREATE MACRO m() AS TABLE SELECT * FROM {reader}('{path}')")
    configure(db, {"allowed_functions": [{"schema_path": ["main"], "name": n} for n in ["m", "read_parquet", "parquet_scan"]]})
    for sql in ["SELECT * FROM v", "SELECT * FROM m()"]:
        assert validate(db, sql)["allowed"]
        assert validate(db, sql, {"blocked_functions": [{"schema_path":["*"],"name":blocked}]})["allowed"]
        result = validate(db, f"{sql}, {reader}('{path}')", {"blocked_functions": [{"schema_path":["*"],"name":blocked}]})
        assert result["allowed"], result
        result = validate(db, f"{sql}, {reader}('{path}')", {"blocked_functions": [{"schema_path":["*"],"name":reader}]})
        assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == reader, result


@pytest.mark.parametrize("reader,substitute,suffix", [("read_csv", "read_csv_auto", "csv"),
                                                    ("read_json", "read_json_auto", "json")])
def test_other_reader_names_remain_independent(db, reader, substitute, suffix):
    configure(db, {"allowed_functions": [{"schema_path": ["main"], "name": reader}]})
    result = validate(db, f"SELECT * FROM '/missing/data.{suffix}'")
    assert result["code"] == "forbidden"
    assert result["violations"][0]["function_name"] == substitute
