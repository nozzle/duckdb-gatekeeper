"""Catalog-only qualification must retain caller attribution at the reader gate."""
import pytest

from support.typed_helpers import configure, validate


@pytest.mark.parametrize("sql", ['SELECT * FROM memory."data.parquet"', "SELECT * FROM 'memory.data.parquet'"])
def test_catalog_qualified_reader_denial_retains_written_path(db, tmp_path, monkeypatch, sql):
    monkeypatch.chdir(tmp_path)
    db.execute("COPY (SELECT 1 x) TO 'memory.data.parquet' (FORMAT PARQUET)")
    configure(db, {"blocked_functions": [{"schema_path": ["main"], "name": "parquet_scan"}]})
    result = validate(db, sql)
    assert result["code"] == "forbidden"
    [violation] = result["violations"]
    assert violation["message"] == "replacement scan function is not allowed: parquet_scan"
    assert violation["table"] == "memory.data.parquet"
    assert violation["catalog"] == "" and violation["schema_path"] == []
