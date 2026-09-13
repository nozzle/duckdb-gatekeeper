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
    blocks = re.findall(r"```sql\n(.*?)```", (ROOT / "README.md").read_text(), re.S)
    observed = []
    for block in runnable_blocks(db, blocks):
        rows = db.execute(block).fetchall()
        if rows:
            observed.append(rows)
    assert observed[1:] == [[(True,)], [("unsupported",)], [("binding",)], [(False,)], [(True,)], [(True,)], [(False,)], [(["md5"],)]]


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
