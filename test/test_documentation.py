"""Run the README and community-descriptor SQL examples in order, including their expected decisions."""
import re
import sys

import duckdb
import pytest

from test_gatekeeper import ROOT, db

sys.path.insert(0, str(ROOT / "scripts"))
from inventory import load

RESPONSE_TYPES = {duckdb.StatementType.SELECT, duckdb.StatementType.CALL}


def display(value):
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return "[" + ", ".join(display(item) for item in value) + "]"
    return "''" if value == "" else str(value)


def assert_response(db, block, result, cells):
    columns = [column[0] for column in result.description]
    rows = result.fetchall()
    if not cells:
        assert db.extract_statements(block)[-1].type not in RESPONSE_TYPES, \
            "Documented queries must show their response"
        return
    assert cells[0] == columns, block
    assert cells[1:] == [[display(value) for value in row] for row in rows], block


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

    for block, table in examples:
        if block not in runnable:
            continue
        result = db.execute(block)
        cells = [[cell.strip() for cell in line.strip().strip("|").split("|")]
                 for line in table.strip().splitlines()]
        if cells:
            assert all(re.fullmatch(r":?-+:?", cell) for cell in cells[1]), table
            del cells[1]
        assert_response(db, block, result, cells)


def hello_world_examples(db):
    """Split docs.hello_world into (statement, expected cells) pairs.

    Comments before a statement explain it; `-- ` lines directly after a statement's
    terminating semicolon are its expected response, header row first, cells separated
    by `|`, ended by a blank line. The descriptor uses canonical two-space YAML like
    scripts/package_release.py expects, so the block scalar is extracted without a YAML
    dependency.
    """
    descriptor = (ROOT / "community/description.yml").read_text()
    block = re.search(r"(?m)^  hello_world: \|\n((?:    [^\n]*\n|\n)*)", descriptor)
    assert block, "community/description.yml docs.hello_world must be a two-space indented block scalar"
    examples, statement, response = [], [], None
    for line in block.group(1).splitlines():
        line = line[4:] if line.startswith("    ") else line.strip()
        if not line:
            response = None
        elif line.startswith("--"):
            if response is not None:
                response.append([cell.strip() for cell in line[2:].split("|")])
        else:
            statement.append(line)
            if line.rstrip().endswith(";"):
                response = []
                examples.append(("\n".join(statement), response))
                statement = []
    assert not statement, "hello_world ends with an unterminated statement"
    for sql, _ in examples:
        assert all(statement.type != duckdb.StatementType.LOAD for statement in db.extract_statements(sql)), \
            "duckdb.org adds INSTALL/LOAD above hello_world; do not repeat them"
    return examples


def test_community_hello_world(db):
    examples = hello_world_examples(db)
    assert len(examples) >= 8
    for statement, cells in examples:
        assert_response(db, statement, db.execute(statement), cells)


def test_community_descriptor_headings():
    """Sub-headings must be ### so they sit beside the site's generated 'About' section."""
    descriptor = (ROOT / "community/description.yml").read_text()
    parts = descriptor.split("  extended_description: |\n", 1)
    assert len(parts) == 2, "community/description.yml docs.extended_description must be a two-space indented block scalar"
    extended = parts[1]
    headings = re.findall(r"(?m)^    (#+) (.+)$", extended)
    assert headings and {level for level, _ in headings} == {"###"}, headings
    # kramdown-style slug: lowercase, drop punctuation, spaces to hyphens.
    anchors = {re.sub(r"[^a-z0-9 -]", "", title.lower()).replace(" ", "-") for _, title in headings}
    for target in re.findall(r"\]\(#([^)]+)\)", extended):
        assert target in anchors, target


def test_default_function_count_in_prose():
    """The default count quoted in the README and descriptor must track the reviewed inventory."""
    _, defaults = load()
    for path in [ROOT / "README.md", ROOT / "community/description.yml"]:
        counts = re.findall(r"\b(\d{3,}) reviewed", path.read_text())
        assert counts and set(counts) == {str(len(defaults))}, (path, counts, len(defaults))


def test_function_metadata_for_generated_docs(db):
    """duckdb.org builds its 'Added Functions' table from duckdb_functions().

    The generator keeps only the first line of `description`, and `parameters` is paired
    positionally with `parameter_types`, which come from an unordered map of named
    parameters; that pairing is only correct while every named option is ANY.
    """
    db.execute("CREATE SCHEMA reporting; CREATE TABLE reporting.orders (amount DOUBLE)")
    rows = db.execute("""SELECT function_name, description, examples, parameters, parameter_types
                         FROM duckdb_functions() WHERE function_name LIKE 'gatekeeper%'
                         ORDER BY function_name""").fetchall()
    assert [row[0] for row in rows] == ["gatekeeper_configure", "gatekeeper_enforce", "gatekeeper_validate"]
    options = ["allowed_tables", "blocked_tables", "use_default_functions", "allowed_functions", "blocked_functions"]
    for name, description, examples, parameters, parameter_types in rows:
        assert description and "\n" not in description and examples, name
        if name == "gatekeeper_enforce":
            assert parameters == [] and parameter_types == []
        else:
            positional = ["sql"] if name == "gatekeeper_validate" else []
            assert sorted(parameters) == sorted(options + positional), name
            assert parameter_types == ["VARCHAR"] * len(positional) + ["ANY"] * len(options), name
        assert db.extract_statements(examples[0])[0].type in RESPONSE_TYPES
        # The enforce example latches the connection it runs on; keep the shared fixture unenforced.
        with db.cursor() as cursor:
            assert cursor.execute(examples[0]).fetchone()[0] is True, examples[0]
    for setting in ["gatekeeper_policy", "gatekeeper_log_only"]:
        assert db.execute("SELECT description FROM duckdb_settings() WHERE name = ?", [setting]).fetchone()[0]


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
