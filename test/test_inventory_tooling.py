import importlib
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

from test_gatekeeper import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
from generate import header, pinned_revision
import schema_check
from inventory import load
from versions import BASELINE_FILENAME


@pytest.mark.parametrize("key,value", [
    ("unexpected", True), ("notes", "not a list"), ("notes", [42]), ("notes", []),
    ("source", {}), ("source", "not a URL"), ("source", "https://"), ("source", "https://host/a b"),
    ("compute", "sum"), ("compute", [None]), ("groups", {"broken": "sum"}),
    ("reviewed_duckdb", "1.0.0"),
])
def test_inventory_schema_rejects_malformed_metadata(tmp_path, key, value):
    shutil.copytree(ROOT / "inventories", tmp_path / "inventories")
    path = tmp_path / "inventories/core.json"
    entry = json.loads(path.read_text())
    entry[key] = value
    path.write_text(json.dumps(entry))
    with pytest.raises(ValueError):
        load(tmp_path)


def test_core_elevated_ownership_survives_without_motherduck(tmp_path):
    shutil.copytree(ROOT / "inventories", tmp_path / "inventories")
    (tmp_path / "inventories/extensions/motherduck.json").unlink()
    entries, defaults = load(tmp_path)
    names = {"read_csv", "read_csv_auto", "read_text", "read_blob", "glob", "sniff_csv", "read_duckdb",
             "pragma_storage_info", "duckdb_table_sample", "which_secret", "query", "query_table",
             "current_setting", "nextval", "checkpoint", "duckdb_views", "histogram", "list_aggregate"}
    assert names <= set(entries["core"]["elevated"])
    assert not names & set(defaults)
    assert len(defaults) == 864


def test_generation_chunks_roundtrip_and_compile(tmp_path):
    data = {"text": ("x\\\"\nλ" * 9000)}
    content = header("fixture", data)
    chunks = re.findall(r'R"DATA\((.*?)\)DATA"', content, re.S)
    assert len(chunks) > 1 and all(len(chunk.encode()) <= 8192 for chunk in chunks)
    assert json.loads("".join(chunks)) == data
    source = tmp_path / "literal.cpp"
    source.write_text('#include <cstdio>\n' + content + '\nint main() { std::fputs(fixture_json, stdout); }\n')
    binary = tmp_path / "literal"
    subprocess.run([os.environ.get("CXX", "c++"), "-std=c++17", str(source), "-o", str(binary)], check=True)
    assert json.loads(subprocess.check_output([str(binary)])) == data


def test_generation_requires_initialized_checkout(tmp_path):
    with pytest.raises(SystemExit, match="Git checkout.*submodule"):
        pinned_revision(tmp_path)
    assert pinned_revision()


def test_inventory_uses_supplied_schema(tmp_path):
    shutil.copytree(ROOT / "inventories", tmp_path / "inventories")
    path = tmp_path / "inventories/schema.json"
    schema = json.loads(path.read_text())
    schema["required"].append("alternate_root_marker")
    path.write_text(json.dumps(schema))
    with pytest.raises(ValueError, match="alternate_root_marker"):
        load(tmp_path)


def test_generation_needs_only_the_standard_library(tmp_path):
    # Distribution images build with a standard-library-only interpreter (-S drops site packages).
    result = subprocess.run([sys.executable, "-S", str(ROOT / "scripts/generate.py"), "--output", str(tmp_path)],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "inventory.hpp").exists() and (tmp_path / "grammar.hpp").exists()


MUTATIONS = [
    ("unexpected", True), ("notes", "not a list"), ("notes", [42]), ("notes", []), ("notes", [""]),
    ("source", {}), ("source", "not a URL"), ("source", "https://"), ("source", "https://host/a b"),
    ("compute", "sum"), ("compute", [None]), ("compute", ["a", "a"]), ("compute", [""]),
    ("groups", {"broken": "sum"}), ("groups", {}), ("reviewed_duckdb", "1.0.0"), ("name", "Core"),
    ("unreviewed_reason", ""), ("unreviewed", ["x"]),
]


def _documents():
    core = json.loads((ROOT / "inventories/core.json").read_text())
    yield core
    for path in sorted((ROOT / "inventories/extensions").glob("*.json")):
        extension = json.loads(path.read_text())
        yield extension
        for key in ["groups", "unreviewed_reason", "source", "notes", "elevated"]:
            mutated = dict(extension)
            mutated.pop(key, None)
            yield mutated
        yield {**extension, "groups": {"a": ["b"]}}
        yield {**extension, "unreviewed": ["x"]}
    for key, value in MUTATIONS:
        yield {**core, key: value}
    for key in list(core):
        mutated = dict(core)
        del mutated[key]
        yield mutated
    yield {**core, "unreviewed": [], "unreviewed_reason": "none"}
    yield {**core, "unreviewed": []}


def test_schema_check_matches_jsonschema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "inventories/schema.json").read_text())
    reference = jsonschema.Draft202012Validator(schema)
    outcomes = set()
    for document in _documents():
        expected = reference.is_valid(document)
        try:
            schema_check.validate(schema, document)
            actual = True
        except schema_check.ValidationError:
            actual = False
        assert actual == expected, json.dumps(document)[:200]
        outcomes.add(expected)
    assert outcomes == {True, False}


@pytest.mark.parametrize("schema", [
    {"type": "string", "format": "uri"},
    {"$ref": "https://example.com/schema"},
    {"type": "string", "$defs": {"unused": {"type": "string", "format": "uri"}}},
    {"type": "string", "if": {"const": "never"}, "then": {"maxLength": 1}},
    {"type": "string", "if": {"type": "string"}, "else": {"maxLength": 1}},
    {"type": "object", "properties": {"unused": {"enum": ["a"]}}},
    {"type": "object", "additionalProperties": {"anyOf": []}},
    {"type": "array", "items": {"type": "string", "maxItems": 1}},
    {"type": "string", "allOf": [{"not": {"format": "uri"}}]},
    {"type": "date"},
])
def test_schema_check_rejects_unsupported_keywords_anywhere(schema):
    # Each schema would accept "x" if the unsupported keyword were ignored; the pre-scan must refuse it.
    with pytest.raises(schema_check.SchemaError):
        schema_check.validate(schema, "x")


@pytest.mark.parametrize("module", ["migrate_unreviewed", "migrate_signature_baseline"])
def test_migrations_import_safe_and_dry_run(module, tmp_path, monkeypatch):
    imported = importlib.import_module(module)
    fixture = tmp_path / "inventories"
    shutil.copytree(ROOT / "inventories", fixture)
    paths = [fixture / "core.json", fixture / "baselines" / BASELINE_FILENAME]
    before = [path.read_bytes() for path in paths]
    monkeypatch.setattr(imported, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", [module])
    if module == "migrate_signature_baseline":
        snapshot = json.loads(paths[1].read_text())
        monkeypatch.setattr(imported, "capture", lambda: snapshot)
    imported.main()
    assert [path.read_bytes() for path in paths] == before
    # Importing either migration must not call the loader/capture or open output files.
    import inventory
    import audit_inventory
    def unexpected(*args, **kwargs):
        pytest.fail("migration did work at import time")
    monkeypatch.setattr(inventory, "load", unexpected)
    monkeypatch.setattr(audit_inventory, "capture", unexpected)
    importlib.reload(imported)
