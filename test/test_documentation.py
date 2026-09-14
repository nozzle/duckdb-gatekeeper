"""Run the README SQL examples in order, including their expected decisions."""
import re

import duckdb
import pytest

from test_gatekeeper import ROOT, db


def runnable_blocks(db, blocks):
    runnable = []
    skipped = 0
    # Parse every block before executing any: INSTALL and LOAD share StatementType.LOAD.
    # This catches extension-loading statements even after comments or other statements.
    for block in blocks:
        statements = db.extract_statements(block)
        if any(statement.type == duckdb.StatementType.LOAD for statement in statements):
            assert block.strip() == "INSTALL gatekeeper FROM community;\nLOAD gatekeeper;", \
                "Unexpected README installation block; update its explicit test contract"
            skipped += 1
        else:
            runnable.append(block)
    assert skipped == 1, "README should have exactly one community installation block"
    return runnable


def test_readme_sql_examples(db):
    examples = re.findall(r"```sql\n(.*?)```(?:\n\n(\|[^\n]*\n(?:\|[^\n]*(?:\n|$))+))?",
                          (ROOT / "README.md").read_text(), re.S)
    runnable = runnable_blocks(db, [block for block, _ in examples])

    def display(value):
        if value is None:
            return "NULL"
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, list):
            return "[" + ", ".join(display(item) for item in value) + "]"
        return "''" if value == "" else str(value)

    for block, table in examples:
        if block not in runnable:
            continue
        result = db.execute(block)
        columns = [column[0] for column in result.description]
        rows = result.fetchall()
        if not table:
            assert db.extract_statements(block)[-1].type not in {
                duckdb.StatementType.SELECT, duckdb.StatementType.CALL
            }, "README queries must show their response as a table"
            continue
        cells = [[cell.strip() for cell in line.strip().strip("|").split("|")]
                 for line in table.strip().splitlines()]
        assert cells[0] == columns, block
        assert all(re.fullmatch(r":?-+:?", cell) for cell in cells[1]), table
        assert cells[2:] == [[display(value) for value in row] for row in rows], block


@pytest.mark.parametrize("block", [
    "-- comment\nINSTALL gatekeeper FROM community;\nLOAD gatekeeper;",
    "LOAD gatekeeper; INSTALL gatekeeper FROM community;",
    "SELECT 1; INSTALL gatekeeper FROM community;",
    "/* comment */ install gatekeeper from community;",
])
def test_installation_drift_rejected_before_execution(db, block):
    with pytest.raises(AssertionError, match="Unexpected README installation block"):
        runnable_blocks(db, [block])


def test_documentation_links():
    for path in [ROOT / "README.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").glob("*.md"))]:
        for target in re.findall(r"\]\(([^)]+)\)", path.read_text()):
            if target.startswith(("http://", "https://", "#")):
                continue
            assert (path.parent / target.split("#", 1)[0]).exists(), (path, target)
