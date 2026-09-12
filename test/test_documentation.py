"""Run the README SQL examples in order, including their expected decisions."""
import re

from test_gatekeeper import ROOT, db


def test_readme_sql_examples(db):
    blocks = re.findall(r"```sql\n(.*?)```", (ROOT / "README.md").read_text(), re.S)
    observed = []
    for block in blocks:
        if block.lstrip().startswith("LOAD "):
            continue
        rows = db.execute(block).fetchall()
        if rows:
            observed.append(rows)
    assert observed[1][0][0]["allowed"] is True
    assert observed[2] == [(False,)]
    assert observed[3] == [("binding",)]
    assert observed[4] == [(True,)]
    assert observed[5] == [(["function is not allowed: md5"],)]
    assert observed[6:] == [[(True,)], [(True,)], [(True,)]]


def test_documentation_links():
    for path in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
        for target in re.findall(r"\]\(([^)]+)\)", path.read_text()):
            if target.startswith(("http://", "https://", "#")):
                continue
            assert (path.parent / target.split("#", 1)[0]).exists(), (path, target)
