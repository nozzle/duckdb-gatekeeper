"""Prove a built loadable's engine guard refuses an engine it was not built for.

Loading the artifact into the engine it was built from shows the load succeeds; it cannot show that the
guard is still compiled in. This script does: it copies the artifact, rewrites its
``GATEKEEPER_BUILD_ENGINE`` stamp in place to name a different engine, and loads the copy into the
build's ``unittest`` runner with DuckDB's own footer check disabled
(``allow_extensions_metadata_mismatch``). The load must fail with Gatekeeper's message. As a control, an
untouched copy made the same way must load and validate.

    python scripts/check_engine_guard.py --extension build/candidate/extension/gatekeeper/gatekeeper.duckdb_extension \\
        --unittest build/candidate/test/unittest

The host is the ``unittest`` runner rather than the shell because it opens databases without loading the
statically linked extensions (``load_extensions = false``): a shell built with Gatekeeper linked in answers
``LOAD`` of a file by that name with "already loaded" and never opens the file. The probe also points
``extension_directory`` at a scratch directory so no installed extension of the same name can be picked up.

The stamp array is NUL padded (scripts/generate.py STAMP_WIDTH), so a rewritten stamp of a different
length keeps the byte count. On macOS the copy is re-signed ad hoc after the rewrite (the kernel kills a
process that pages in code whose signature no longer matches) and DuckDB's trailing metadata footer, which
sits after the Mach-O image, is re-appended.
"""
import argparse
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

STAMP = re.compile(rb"GATEKEEPER_BUILD_ENGINE ([^\s\0]+) ([^\s\0]+)\0+")
REFUSAL = "was built for DuckDB"


def stamp(data: bytes):
    matches = STAMP.findall(data)
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one GATEKEEPER_BUILD_ENGINE stamp, found {len(matches)}")
    return tuple(field.decode() for field in matches[0])


def write_copy(extension: Path, target: Path, version: str, source_id: str):
    """A copy of ``extension`` at ``target`` whose stamp names (version, source_id), byte count kept."""
    data = extension.read_bytes()
    match = STAMP.search(data)
    replacement = b"GATEKEEPER_BUILD_ENGINE %s %s" % (version.encode(), source_id.encode())
    if len(replacement) >= match.end() - match.start():
        raise SystemExit("rewritten stamp does not fit the padded array")
    replacement = replacement.ljust(match.end() - match.start(), b"\0")
    target.write_bytes(data[:match.start()] + replacement + data[match.end():])
    if platform.system() == "Darwin":
        listing = subprocess.check_output(["otool", "-l", str(target)], text=True)
        if "LC_CODE_SIGNATURE" in listing:
            signature = listing[listing.index("LC_CODE_SIGNATURE"):]
            end = sum(int(re.search(rf"{field}\s+(\d+)", signature)[1]) for field in ("dataoff", "datasize"))
            image, footer = target.read_bytes()[:end], target.read_bytes()[end:]
            target.write_bytes(image)
            subprocess.run(["codesign", "--force", "--sign", "-", str(target)], check=True, capture_output=True)
            target.write_bytes(target.read_bytes() + footer)


def probe(unittest: Path, root: Path, name: str, body: str):
    """Run one generated sqllogictest under ``root`` (its own test tree, via --test-dir); returns (ok, output)."""
    (root / "test" / "sql").mkdir(parents=True, exist_ok=True)
    (root / "test" / "sql" / f"{name}.test").write_text(body)
    result = subprocess.run([str(unittest), "--test-dir", str(root), f"test/sql/{name}.test"],
                            capture_output=True, text=True)
    return result.returncode == 0, result.stdout + result.stderr


def check(extension: Path, unittest: Path) -> list:
    version, source_id = stamp(extension.read_bytes())
    release = "-dev" not in version
    # Alter the one field the guard compares for this kind of engine, formatted as the guard prints it.
    altered = version if release else source_id
    altered = altered[:-1] + ("0" if altered[-1] != "0" else "1")
    problems = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        settings = (f"statement ok\nSET extension_directory = '{root / 'extensions'}';\n\n"
                    "statement ok\nSET allow_extensions_metadata_mismatch = true;\n\n")
        tampered = root / "tampered" / extension.name
        tampered.parent.mkdir()
        write_copy(extension, tampered, *((altered, source_id) if release else (version, altered)))
        ok, output = probe(unittest, root, "tampered",
                           settings + f"statement error\nLOAD '{tampered}';\n----\n{REFUSAL}\n")
        if not ok:
            problems.append("the guard did not refuse a copy stamped for another engine:\n" + output.strip()[-1500:])
        intact = root / "intact" / extension.name
        intact.parent.mkdir()
        write_copy(extension, intact, version, source_id)
        ok, output = probe(unittest, root, "intact",
                           settings + f"statement ok\nLOAD '{intact}';\n\n"
                           "query I\nSELECT allowed FROM gatekeeper_validate('SELECT 1');\n----\ntrue\n")
        if not ok:
            problems.append("the same copy with its stamp intact did not load and validate:\n" + output.strip()[-1500:])
    if not problems:
        print(f"{extension}: guard refuses another engine and accepts {version} ({source_id})")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--extension", type=Path, required=True)
    parser.add_argument("--unittest", type=Path, required=True, help="the unittest runner built from the same engine")
    args = parser.parse_args(argv)
    problems = check(args.extension.resolve(), args.unittest.resolve())
    for problem in problems:
        print("::error::" + problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
