"""The portable SQL form of the loadable smoke (scripts/smoke/*.sql) against the local artifact.

The distribution workflow runs these files against every shipped artifact through three drivers: the Python
package (scripts/smoke_loadable.py), the DuckDB CLI for the musl targets (scripts/smoke_cli.sh), and the CRAN
package for MinGW (scripts/smoke_loadable.R). Running them here keeps the files executable on the engines the
suite covers before a change reaches those hosts, and checks the paragraph conventions the drivers rely on.
"""
from pathlib import Path

import pytest

from smoke_loadable import DIRECTIVE, SMOKE_DIR, run, statements
from support.artifact import connect


def test_loadable_half_passes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with connect() as host:
        run(SMOKE_DIR / "loadable.sql", {"host": host})
    assert (tmp_path / "gatekeeper_smoke.parquet").exists(), "the replacement-scan check writes into the working directory"


def test_enforced_half_passes():
    with connect() as host, host.cursor() as agent:
        run(SMOKE_DIR / "enforced.sql", {"host": host, "agent": agent})


def test_loadable_half_needs_one_connection():
    """The CLI driver reads loadable.sql as one stdin script on one connection, so no paragraph may name the
    agent or expect an error (a failing statement is the only failure signal under -bail)."""
    for statement in statements(SMOKE_DIR / "loadable.sql"):
        assert statement.connection == "host" and statement.error is None, statement


def test_enforced_half_names_every_connection():
    """Every paragraph of enforced.sql carries a directive, and the agent latches before anything it runs."""
    seen_enforce = False
    text = (SMOKE_DIR / "enforced.sql").read_text()
    directives = [line for line in text.splitlines() if line.startswith("-- @")]
    parsed = statements(SMOKE_DIR / "enforced.sql")
    assert len(directives) == len(parsed), "one directive per statement"
    assert all(DIRECTIVE.match(line) for line in directives)
    for statement in parsed:
        if statement.connection == "agent":
            if "gatekeeper_enforce()" in statement.sql:
                seen_enforce = True
            assert seen_enforce, f"agent statement before gatekeeper_enforce(): {statement.sql}"
    assert {s.connection for s in parsed} == {"host", "agent"}
    assert any(s.error for s in parsed), "the file exercises expected errors"


def test_statement_parsing_conventions(tmp_path):
    """Comment lines are dropped, the trailing semicolon too, and directives are read from any comment line
    of the paragraph, so a logged statement equals the text a reader sees in the file."""
    path = tmp_path / "sample.sql"
    path.write_text(
        "-- header comment\n"
        "\n"
        "SELECT 1;\n"
        "\n"
        "-- explanation\n"
        "-- @agent expect error: denied\n"
        "SELECT 2\n"
        "  FROM t;\n"
        "\n"
        "-- @host\n"
        "SELECT 3;\n"
    )
    parsed = statements(path)
    assert [(s.connection, s.sql, s.error, s.line) for s in parsed] == [
        ("host", "SELECT 1", None, 3),
        ("agent", "SELECT 2\n  FROM t", "denied", 5),
        ("host", "SELECT 3", None, 10),
    ]


def test_expected_error_must_match(tmp_path):
    """A statement that fails with another error, or succeeds when an error is expected, fails the run, as
    does a check whose error() fires."""
    def run_text(host, text):
        path = tmp_path / "sample.sql"
        path.write_text(text)
        run(path, {"host": host})

    with connect() as host:
        with pytest.raises(SystemExit, match="wrong error"):
            run_text(host, "-- @host expect error: nope\nSELECT error('something else');\n")
        with pytest.raises(SystemExit, match="succeeded, expected an error"):
            run_text(host, "-- @host expect error: nope\nSELECT 1;\n")
        with pytest.raises(SystemExit, match="boom"):
            run_text(host, "SELECT error('boom');\n")
