"""Run the README and community-descriptor SQL examples in order, including their expected decisions."""
import re

import duckdb
import pytest

import benchmark
from descriptor import block_scalar
from inventory import load
from support.artifact import EXTENSION, ROOT
from support.headers import control_plane_names, never_bind_names
from versions import EXTENSION_VERSION, SUPPORTED_DUCKDB

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
    by `|`, ended by a blank line. scripts/descriptor.py reads the block scalar the same
    way scripts/package_release.py reads the pins, without a YAML dependency.
    """
    examples, statement, response = [], [], None
    for line in block_scalar("docs", "hello_world"):
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


def test_never_bind_list_in_prose_is_the_header():
    """docs/security.md spells out the never-bind list and, with the README, its control-plane subset; each must
    be exactly the header's set. A count would let a swapped name pass."""
    section = (ROOT / "docs/security.md").read_text().split("### Never-bind functions", 1)[1]
    listed = re.search(r"```\n(.*?)```", section, re.S)[1].split()
    assert len(listed) == len(set(listed)), "a name is listed twice"
    assert set(listed) == never_bind_names()
    subset = re.search(r"The control-plane subset \((.*?)\)", section, re.S)[1]
    assert set(re.findall(r"`([a-z_]+)`", subset)) == control_plane_names()
    readme = re.search(r"Gatekeeper's own control plane, (.*?), which is\s+refused", (ROOT / "README.md").read_text(), re.S)[1]
    assert set(re.findall(r"`([a-z_]+)`", readme)) == control_plane_names()
    assert control_plane_names() < never_bind_names()


def test_default_function_count_in_prose():
    """The default count quoted in the README and descriptor must track the reviewed inventory."""
    _, defaults = load()
    for path in [ROOT / "README.md", ROOT / "community/description.yml"]:
        counts = re.findall(r"\b(\d{3,}) reviewed", path.read_text())
        assert counts and set(counts) == {str(len(defaults))}, (path, counts, len(defaults))


def benchmark_table(text, heading):
    """The table under ``heading`` as rows of cells, separator row dropped, and the whitespace-normalized
    paragraph after it: the shape scripts/benchmark.py prints, however the document wraps it."""
    section = re.split(r"(?m)^#", text.split(heading, 1)[1], maxsplit=1)[0]
    match = re.search(r"(?ms)^((?:\|[^\n]*\n)+)\n(.+?)\n\n", section)
    assert match, heading
    rows = [[cell.strip() for cell in line.strip().strip("|").split("|")] for line in match[1].splitlines()]
    assert all(re.fullmatch(r":?-+:?", cell) for cell in rows[1]), rows[1]
    del rows[1]
    return rows, " ".join(match[2].split())


def test_benchmark_table_is_the_script_output():
    """The README and the descriptor carry one benchmark table: the same cells and footnote in both, the rows
    and columns scripts/benchmark.py measures, and the engine and extension the numbers were taken on named in
    the footnote so a stale table is visible. The values themselves are the machine's; see the repinning
    procedure for when they are regenerated."""
    readme = benchmark_table(prose(ROOT / "README.md"), "\n## Benchmarks\n")
    descriptor = benchmark_table("\n".join(block_scalar("docs", "extended_description")), "\n### Benchmarks\n")
    assert readme == descriptor
    rows, footnote = readme
    assert rows[0] == ["", *benchmark.WORKLOADS]
    assert [row[0] for row in rows[1:]] == list(benchmark.MODES)
    assert all(len(row) == len(rows[0]) for row in rows)
    assert f"after {benchmark.WARMUP} warm-ups" in footnote
    assert f"DuckDB {SUPPORTED_DUCKDB}, Gatekeeper {EXTENSION_VERSION}." in footnote


def test_benchmark_script_prints_that_table():
    """One iteration end to end: every mode runs every workload, the denied copies are refused as forbidden,
    and the Markdown parses into the shape the documents carry."""
    iterations = 1
    rows, footnote = benchmark_table("\n" + benchmark.markdown(benchmark.measure(EXTENSION, iterations), iterations)
                                     + "\n", "\n")
    assert rows[0] == ["", *benchmark.WORKLOADS]
    assert [row[0] for row in rows[1:]] == list(benchmark.MODES)
    for row in rows[1:]:
        for label, value in zip(rows[0][1:], row[1:]):
            assert re.fullmatch(r"\d+(\.\d)? (µs|ms)( \([+−]\d+(\.\d)? (µs|ms)\))?", value), (row[0], label, value)
    assert f"Median of {iterations} runs" in footnote and duckdb.__version__ in footnote


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


def prose(path):
    """The Markdown outside fenced code blocks: a `# comment` in a shell block is not a heading."""
    return re.sub(r"(?ms)^ {0,3}(```|~~~).*?^ {0,3}\1[^\n]*$", "", path.read_text())


def heading_anchors(path):
    """The fragment identifiers GitHub gives ``path``'s ATX headings: lowercase, keep letters, digits, spaces,
    hyphens and underscores, spaces to hyphens, and a repeated title gets -1, -2, ... in order."""
    anchors, seen = set(), {}
    for title in re.findall(r"(?m)^ {0,3}#{1,6} +(.+?) *$", prose(path)):
        slug = re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")
        anchors.add(slug if slug not in seen else f"{slug}-{seen[slug]}")
        seen[slug] = seen.get(slug, 0) + 1
    return anchors


def test_documentation_links():
    """Every relative link in the project's Markdown names a file that exists and, when it carries a fragment,
    a heading in that file. Symlinked duplicates (CLAUDE.md) are checked through their target."""
    pages = [path for directory in [ROOT, ROOT / "docs", ROOT / "inventories", ROOT / "test/wasm"]
             for path in sorted(directory.glob("*.md")) if not path.is_symlink()]
    assert {page.name for page in pages} >= {"README.md", "CONTRIBUTING.md", "AGENTS.md", "SECURITY.md", "security.md"}
    for path in pages:
        for target in re.findall(r"\]\(([^)]+)\)", prose(path)):
            if target.startswith(("http://", "https://")):
                continue
            file, _, fragment = target.partition("#")
            page = (path.parent / file) if file else path
            assert page.exists(), (path, target)
            if fragment:
                assert page.suffix == ".md" and fragment in heading_anchors(page), (path, target)
