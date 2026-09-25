"""Only the explicitly reviewed Parquet reader pair shares a permission."""
import pytest

from support.typed_helpers import configure, validate


@pytest.mark.parametrize("global_name", ["read_parquet", "PARQUET_SCAN"])
@pytest.mark.parametrize("request_name", ["READ_PARQUET", "parquet_scan"])
def test_either_alias_authorizes_both_spellings_and_shorthand(db, tmp_path, global_name, request_name):
    path = str(tmp_path / "data.parquet").replace("'", "''")
    db.execute(f"COPY (SELECT 1 x) TO '{path}' (FORMAT PARQUET)")
    configure(db, {"allowed_functions": [{"schema_path": ["*"], "name": global_name}]})
    for source in [f"read_parquet('{path}')", f"parquet_scan('{path}')", f"'{path}'"]:
        result = validate(db, f"SELECT * FROM {source}", {"allowed_functions": [{"schema_path": ["*"], "name": request_name}]})
        assert result["allowed"], result


@pytest.mark.parametrize("blocked", ["read_parquet", "PARQUET_SCAN"])
@pytest.mark.parametrize("global_block", [False, True])
def test_either_alias_blocks_both_spellings_and_shorthand_before_io(db, blocked, global_block):
    blocks = {"blocked_functions": [blocked]}
    configure(db, {"allowed_functions": [{"schema_path": ["*"], "name": n} for n in ["read_parquet", "parquet_scan"]], **(blocks if global_block else {})})
    request = {"blocked_functions": []} if global_block else blocks
    for source in ["read_parquet('/missing/data.parquet')", "parquet_scan('/missing/data.parquet')",
                   "'/missing/data.parquet'"]:
        result = validate(db, f"SELECT * FROM {source}", request)
        assert result["code"] == "forbidden" and result["error_message"] == "", result
        assert result["violations"][0]["function_name"] == "read_parquet"


@pytest.mark.parametrize("reader,blocked", [("read_parquet", "parquet_scan"), ("parquet_scan", "read_parquet")])
def test_alias_blocks_do_not_reach_inside_trusted_expansions(db, tmp_path, reader, blocked):
    # The reader a host view or table macro names is that definition's own under either alias; a block under
    # either alias still reaches the caller's own call of either spelling next to it.
    path = str(tmp_path / "data.parquet").replace("'", "''")
    db.execute(f"COPY (SELECT 1 x) TO '{path}' (FORMAT PARQUET)")
    db.execute(f"CREATE VIEW v AS SELECT * FROM {reader}('{path}')")
    db.execute(f"CREATE MACRO m() AS TABLE SELECT * FROM {reader}('{path}')")
    configure(db, {"allowed_functions": [{"schema_path": ["*"], "name": n} for n in ["m", "read_parquet"]]})
    for sql in ["SELECT * FROM v", "SELECT * FROM m()"]:
        assert validate(db, sql)["allowed"]
        assert validate(db, sql, {"blocked_functions": [blocked]})["allowed"]
        result = validate(db, f"{sql}, {reader}('{path}')", {"blocked_functions": [blocked]})
        assert result["code"] == "forbidden" and result["violations"][0]["function_name"] == "read_parquet", result


@pytest.mark.parametrize("reader,substitute,suffix", [("read_csv", "read_csv_auto", "csv"),
                                                    ("read_json", "read_json_auto", "json")])
def test_other_reader_names_remain_independent(db, reader, substitute, suffix):
    configure(db, {"allowed_functions": [{"schema_path": ["*"], "name": reader}]})
    result = validate(db, f"SELECT * FROM '/missing/data.{suffix}'")
    assert result["code"] == "forbidden"
    assert result["violations"][0]["function_name"] == substitute
