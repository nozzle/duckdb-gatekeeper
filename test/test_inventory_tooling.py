import json
import os
import re
import shutil
import subprocess
import sys

import pytest

from generate import grammar, header
from inventory import check_sources, load
import schema_check
from support.artifact import ROOT
from support.toolchain import compile_cpp, git, repository


@pytest.mark.parametrize("key,value", [
    ("unexpected", True), ("notes", "not a list"), ("notes", [42]), ("notes", []),
    ("source", {}), ("source", "not a URL"), ("source", "https://"), ("source", "https://host/a b"),
    ("compute", "sum"), ("compute", [None]), ("groups", {"broken": "sum"}),
    ("reviewed_duckdb", "not-a-version"),
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
    assert len(defaults) == 953


def test_generation_chunks_roundtrip_and_compile(tmp_path):
    data = {"text": ("x\\\"\nλ" * 9000)}
    content = header("fixture", data)
    chunks = re.findall(r'R"DATA\((.*?)\)DATA"', content, re.S)
    assert len(chunks) > 1 and all(len(chunk.encode()) <= 8192 for chunk in chunks)
    assert json.loads("".join(chunks)) == data
    source = tmp_path / "literal.cpp"
    source.write_text('#include <cstdio>\n' + content + '\nint main() { std::fputs(fixture_json, stdout); }\n')
    binary = compile_cpp([source], tmp_path / "literal")
    assert json.loads(subprocess.check_output([str(binary)])) == data


def test_generation_uses_build_source_without_git_or_matching_review(tmp_path):
    source = tmp_path / "engine"
    relative = "src/include/duckdb/storage/serialization"
    shutil.copytree(ROOT / "duckdb" / relative, source / relative)
    path = source / relative / "parsed_expression.json"
    data = json.loads(path.read_text())
    expression = next(entry for entry in data if entry["class"] == "ConstantExpression")
    expression["members"].append({"id": 999, "name": "candidate_field", "type": "string"})
    path.write_text(json.dumps(data))
    output = tmp_path / "generated"
    subprocess.run([sys.executable, "-S", str(ROOT / "scripts/generate.py"),
                    "--duckdb-source", str(source), "--output", str(output)], check=True)
    assert "candidate_field" in (output / "grammar.hpp").read_text()
    assert "candidate_field" not in grammar()["rules"]["ConstantExpression"]["fields"]
    expression["members"][-1]["type"] = "UnsupportedCandidateType"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="Unreviewed field type"):
        grammar(source)


def test_review_version_is_historical_provenance(tmp_path):
    shutil.copytree(ROOT / "inventories", tmp_path / "inventories")
    path = tmp_path / "inventories/core.json"
    entry = json.loads(path.read_text())
    entry["reviewed_duckdb"] = "1.0.0"
    path.write_text(json.dumps(entry))
    assert load(tmp_path)[1] == load()[1]


def test_reviewed_sources_match_engine_descriptors():
    entries, _ = load()
    check_sources(entries)
    entries["spatial"]["source"] = entries["spatial"]["source"].replace("/tree/", "/tree/0")
    with pytest.raises(ValueError, match="Reviewed source.*spatial"):
        check_sources(entries)


def test_source_check_rejects_conditional_pins(tmp_path):
    entries, _ = load()
    descriptor = tmp_path / "duckdb/.github/config/extensions/spatial.cmake"
    descriptor.parent.mkdir(parents=True)
    descriptor.write_text((ROOT / "duckdb/.github/config/extensions/spatial.cmake").read_text() +
                          "\nif(WIN32)\n GIT_TAG " + "0" * 40 + "\nendif()\n")
    with pytest.raises(ValueError, match="Ambiguous platform-conditional.*spatial"):
        check_sources({"spatial": entries["spatial"]}, tmp_path)


def test_audit_comparison_checks_reviewed_sources(monkeypatch, tmp_path):
    import audit_inventory
    candidate = tmp_path / "candidate.json"
    candidate.write_text("{}")
    monkeypatch.setattr(sys, "argv", ["audit_inventory.py", "--check-sources", "--candidate", str(candidate)])

    def reject(entries, **kwargs):
        raise ValueError("source pin drift")

    monkeypatch.setattr(audit_inventory, "check_sources", reject)
    with pytest.raises(ValueError, match="source pin drift"):
        audit_inventory.main()


def test_source_check_accepts_explicit_historical_checkout(monkeypatch, tmp_path):
    entries, _ = load()
    # An external review checkout works even if the caller has no duckdb submodule.
    check_sources(entries, tmp_path, duckdb_source=ROOT / "duckdb")
    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: "0" * 40)
    with pytest.raises(ValueError, match="historical review checkout"):
        check_sources(entries)


def test_source_check_explains_missing_checkout(tmp_path):
    entries, _ = load()
    with pytest.raises(ValueError, match="clone with --recurse-submodules or pass --source-checkout"):
        check_sources(entries, tmp_path)


def test_binary_only_review_cannot_grant_defaults(tmp_path):
    shutil.copytree(ROOT / "inventories", tmp_path / "inventories")
    path = tmp_path / "inventories/extensions/motherduck.json"
    entry = json.loads(path.read_text())
    assert "binary_review" in entry and entry["compute"] == []
    entry["compute"] = ["md_version"]
    entry["elevated"].remove("md_version")
    path.write_text(json.dumps(entry))
    with pytest.raises(ValueError, match="invalid inventory motherduck.json"):
        load(tmp_path)


def test_generation_bakes_build_engine_identity(tmp_path):
    output = tmp_path / "generated"
    subprocess.run([sys.executable, "-S", str(ROOT / "scripts/generate.py"), "--output", str(output),
                    "--engine-version-label", "v1.5.6-dev150", "--engine-source-id", "a3cd0deed1"], check=True)
    text = (output / "version.hpp").read_text()
    assert re.search(r'BUILD_ENGINE_STAMP\[\d+\] = "GATEKEEPER_BUILD_ENGINE v1.5.6-dev150 a3cd0deed1"', text)
    for flag, value in [("--engine-version-label", "v0.0.1; system(\"x\")"), ("--engine-source-id", "not-hex"),
                        ("--engine-source-id", "a"), ("--engine-source-id", "")]:
        result = subprocess.run([sys.executable, "-S", str(ROOT / "scripts/generate.py"), "--output", str(output),
                                 flag, value], capture_output=True, text=True)
        assert result.returncode != 0 and "Refusing to bake" in result.stderr


def test_engine_selection_defaults(tmp_path):
    import argparse
    from engine import add_engine_arguments, checkout_revision, engine_cmake_flags, engine_source
    from versions import SUPPORTED_DUCKDB, SUPPORTED_DUCKDB_REVISION
    parser = argparse.ArgumentParser()
    add_engine_arguments(parser)
    # The pinned submodule is stamped with the release pin so shallow clones never produce v0.0.1.
    assert checkout_revision(ROOT / "duckdb") == SUPPORTED_DUCKDB_REVISION
    assert engine_cmake_flags(parser.parse_args([])) == ["-DOVERRIDE_GIT_DESCRIBE=v" + SUPPORTED_DUCKDB]
    assert engine_source(parser.parse_args([])) == (ROOT / "duckdb").resolve()
    # Other checkouts use their own Git metadata unless told otherwise. The cache entry is always
    # written (as empty) because an omitted -D would leave an earlier override in CMakeCache.txt.
    external = parser.parse_args(["--duckdb-source", str(tmp_path)])
    assert checkout_revision(tmp_path) is None
    # A directory inside this repository that is not its own checkout (an uninitialized submodule, a build
    # tree) must not resolve to Gatekeeper's own commit through Git's parent discovery.
    assert checkout_revision(ROOT / "scripts") is None
    assert checkout_revision(ROOT / "does-not-exist") is None
    assert engine_cmake_flags(external) == ["-DOVERRIDE_GIT_DESCRIBE="]
    assert engine_source(external) == tmp_path.resolve()
    assert engine_cmake_flags(parser.parse_args(["--duckdb-source", str(tmp_path), "--duckdb-version", "v1.5.6"])) == [
        "-DOVERRIDE_GIT_DESCRIBE=v1.5.6"]
    assert engine_cmake_flags(parser.parse_args(["--duckdb-version", ""])) == ["-DOVERRIDE_GIT_DESCRIBE="]


def test_engine_selection_follows_the_revision_not_the_path(tmp_path):
    """The pin is supplied for the pinned commit, wherever it is checked out, and never for another commit in
    the submodule directory: a path-based rule would label a rebuild for a newer engine as the pinned release."""
    import argparse
    from engine import add_engine_arguments, engine_version
    from versions import SUPPORTED_DUCKDB, SUPPORTED_DUCKDB_REVISION
    parser = argparse.ArgumentParser()
    add_engine_arguments(parser)
    if not shutil.which("git"):
        pytest.skip("git not installed")
    for name, revision in (("pinned", SUPPORTED_DUCKDB_REVISION), ("other", "0" * 40)):
        # HEAD at the wanted commit id without needing that object: a detached ref is enough for rev-parse.
        repo = tmp_path / name
        repository(repo, head=revision)
        assert engine_version(parser.parse_args(["--duckdb-source", str(repo)])) == (
            "v" + SUPPORTED_DUCKDB if name == "pinned" else None)
    assert engine_version(parser.parse_args(["--duckdb-source", str(tmp_path / "other"), "--duckdb-version", "v1.5.6"])) == "v1.5.6"


def test_engine_override_does_not_survive_reconfigure(tmp_path):
    """Override -> automatic in a reused build directory must not keep the cached override."""
    import argparse
    from engine import add_engine_arguments, engine_cmake_flags
    parser = argparse.ArgumentParser()
    add_engine_arguments(parser)
    (tmp_path / "CMakeLists.txt").write_text(
        'cmake_minimum_required(VERSION 3.15)\nproject(probe NONE)\n'
        'file(WRITE "${CMAKE_BINARY_DIR}/override.txt" "${OVERRIDE_GIT_DESCRIBE}")\n')
    cmake = shutil.which("cmake", path=os.pathsep.join([str(ROOT / ".venv/bin"), os.environ.get("PATH", "")]))
    if not cmake:
        pytest.skip("cmake not installed")
    build = tmp_path / "build"
    for arguments in (["--duckdb-source", str(tmp_path), "--duckdb-version", "v1.5.4"],
                      ["--duckdb-source", str(tmp_path)]):
        flags = engine_cmake_flags(parser.parse_args(arguments))
        subprocess.run([cmake, "-S", str(tmp_path), "-B", str(build), *flags], check=True, capture_output=True)
    assert (build / "override.txt").read_text() == ""


def test_audit_reports_drift_without_requiring_reclassification(monkeypatch, tmp_path, capsys):
    import audit_inventory
    from versions import BASELINE_FILENAME
    snapshot = json.loads((ROOT / "inventories/baselines" / BASELINE_FILENAME).read_text())
    snapshot["duckdb_version"] = "v9.0.0"
    snapshot["functions"].append({"name": "candidate_new_function", "parameters": []})
    candidate = tmp_path / "candidate.json"
    candidate.write_text(json.dumps(snapshot))
    monkeypatch.setattr(sys, "argv", ["audit_inventory.py", "--candidate", str(candidate)])
    audit_inventory.main()
    report = json.loads(capsys.readouterr().out)
    assert report["version_changed"]
    assert report["unclassified_runtime_names"] == ["candidate_new_function"]
    assert "candidate_new_function" not in load()[1]
    monkeypatch.setattr(sys, "argv", ["audit_inventory.py", "--strict", "--candidate", str(candidate)])
    with pytest.raises(SystemExit, match="historical baseline"):
        audit_inventory.main()


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


@pytest.mark.parametrize("module", ["versions", "schema_check", "inventory", "generate", "engine"])
def test_generation_path_imports_without_development_dependencies(module):
    # The modules CMake runs at configure time, and the engine selection the build scripts share, import with
    # duckdb and pytest made unimportable; scripts/artifact.py, which imports duckdb, must not be reachable.
    code = ("import sys; sys.modules['duckdb'] = None; sys.modules['pytest'] = None; sys.modules['artifact'] = None; "
            f"import {module}")
    result = subprocess.run([sys.executable, "-S", "-c", code], cwd=ROOT / "scripts", capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("key,value", [("unexpected", True), ("source", "not a URL"), ("notes", [])])
def test_standard_library_validation_still_rejects_malformed_inventories(tmp_path, key, value):
    # The same strictness without jsonschema: -S ensures only the bundled validator is available.
    shutil.copytree(ROOT / "inventories", tmp_path / "inventories")
    path = tmp_path / "inventories/core.json"
    entry = json.loads(path.read_text())
    entry[key] = value
    path.write_text(json.dumps(entry))
    code = ("import sys, pathlib; sys.path.insert(0, 'scripts'); from inventory import load; "
            f"load(pathlib.Path({str(tmp_path)!r}))")
    result = subprocess.run([sys.executable, "-S", "-c", code], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0
    assert "invalid inventory core.json" in result.stderr and "jsonschema" not in result.stderr


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


def test_sanitized_runner_rejects_engines_the_pinned_package_cannot_load(tmp_path):
    from versions import SUPPORTED_DUCKDB
    result = subprocess.run([sys.executable, str(ROOT / "scripts/test_sanitized.py"), "--duckdb-source", str(tmp_path)],
                            capture_output=True, text=True)
    assert result.returncode == 2 and f"pinned duckdb=={SUPPORTED_DUCKDB} Python package" in result.stderr
    result = subprocess.run([sys.executable, str(ROOT / "scripts/test_sanitized.py"), "--duckdb-version", "v1.5.4"],
                            capture_output=True, text=True)
    assert result.returncode == 2


def test_wasm_container_mounts_engine_git_metadata(tmp_path):
    """An engine linked as a worktree under root still needs its external Git common directory mounted."""
    from build_wasm import container_mounts
    root, engine = tmp_path / "project", tmp_path / "engine"
    repository(root)
    repository(engine)
    candidate = root / "build/candidate-source"
    candidate.parent.mkdir(parents=True)
    git(engine, "worktree", "add", "-q", str(candidate))
    root, engine, candidate = root.resolve(), engine.resolve(), candidate.resolve()
    volumes = lambda mounts: [mounts[i + 1] for i in range(0, len(mounts), 2)]
    # Under-root linked worktree: the source is already covered by root, but its metadata is not.
    assert volumes(container_mounts(root, candidate)) == [f"{root}:{root}", f"{engine / '.git'}:{engine / '.git'}:ro"]
    # External primary checkout: mount it, and its own metadata is inside it.
    assert volumes(container_mounts(root, engine)) == [f"{root}:{root}", f"{engine}:{engine}"]
    # The pinned submodule of the real primary checkout needs nothing beyond root and root's metadata.
    real_root = ROOT.resolve()
    assert volumes(container_mounts(real_root, real_root / "duckdb"))[0] == f"{real_root}:{real_root}"
