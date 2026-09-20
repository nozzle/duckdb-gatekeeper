"""Package the complete distribution run as unsigned, engine-specific release assets."""
import argparse
import hashlib
from pathlib import Path
import re
import zipfile

import descriptor as community
from versions import SUPPORTED_DUCKDB, SUPPORTED_DUCKDB_REVISION, load_versions

ROOT = Path(__file__).resolve().parents[1]
# Keep aligned with MainDistributionPipeline.yml and the community descriptor.
PLATFORMS = (
    "linux_amd64", "linux_arm64", "linux_amd64_musl", "linux_arm64_musl",
    "osx_amd64", "osx_arm64", "windows_amd64", "windows_arm64",
    "windows_amd64_mingw", "wasm_eh",
)


def changelog_sections(text):
    """CHANGELOG.md as {heading version: body} in file order; ``Unreleased`` is the pending section."""
    parts = re.split(r"(?m)^## (\S+)[^\n]*\n", text)
    if len(parts) < 3:
        raise ValueError("CHANGELOG.md must have at least one '## <version>' section")
    headings = parts[1::2]
    duplicates = sorted({heading for heading in headings if headings.count(heading) > 1})
    if duplicates:
        raise ValueError(f"CHANGELOG.md has more than one section for {duplicates}")
    return {parts[i]: parts[i + 1].strip() for i in range(1, len(parts), 2)}


def release_version(tag):
    metadata = load_versions(ROOT)
    version = metadata["GATEKEEPER_VERSION"]
    if (metadata["GATEKEEPER_DUCKDB_VERSION"] != SUPPORTED_DUCKDB or
            metadata["GATEKEEPER_DUCKDB_REVISION"] != SUPPORTED_DUCKDB_REVISION):
        raise ValueError("Loaded and on-disk engine metadata must agree")

    descriptor = community.text(ROOT)
    if SUPPORTED_DUCKDB_REVISION not in descriptor or f"DuckDB {SUPPORTED_DUCKDB}" not in descriptor:
        raise ValueError("community/description.yml must cite the pinned DuckDB version and source revision "
                         "from versions.cmake")
    descriptor_version = community.scalar("extension", "version", descriptor)
    descriptor_ref = community.scalar("repo", "ref", descriptor)
    if descriptor_version != version or descriptor_ref != f"v{version}":
        raise ValueError(f"Community descriptor version {descriptor_version}, ref {descriptor_ref}, "
                         f"and release v{version} must agree")
    # The descriptor's documentation links pin the release they describe; one left at the previous tag would
    # show duckdb.org readers documentation for a binary that does not have the feature, or the reverse.
    stale = sorted(set(re.findall(r"github\.com/nozzle/duckdb-gatekeeper/blob/([^/]+)/", descriptor)) - {f"v{version}"})
    if stale:
        raise ValueError(f"Community descriptor links refer to {stale}; every blob/ link must name v{version}")
    if tag and tag != f"v{version}":
        raise ValueError(f"Tag {tag!r} and version {version} must agree")
    sections = changelog_sections((ROOT / "CHANGELOG.md").read_text())
    # The pending section is always present: between releases it is where the next change goes, and the
    # release commit leaves it empty rather than removing it.
    if "Unreleased" not in sections:
        raise ValueError("CHANGELOG.md must keep a '## Unreleased' section (empty on a release commit)")
    if tag:
        # A release ships with its notes written: this version's section exists with content, and nothing is left
        # pending under Unreleased.
        if not sections.get(version):
            raise ValueError(f"CHANGELOG.md has no '## {version}' section with content")
        if sections["Unreleased"]:
            raise ValueError("CHANGELOG.md still lists entries under '## Unreleased'; move them to the release section")
    return version


def package_release(tag, artifacts, output):
    version = release_version(tag)
    tag = tag or f"v{version}"
    prefix = f"gatekeeper-v{SUPPORTED_DUCKDB}-extension-"
    expected = {prefix + platform for platform in PLATFORMS}
    actual = {path.name for path in artifacts.iterdir()}
    if actual != expected:
        raise ValueError(f"Incomplete distribution: missing {sorted(expected - actual)}, unexpected {sorted(actual - expected)}")

    # Validate the entire input before producing anything that could be published.
    binaries = []
    for platform in PLATFORMS:
        directory = artifacts / (prefix + platform)
        name = "gatekeeper.duckdb_extension" + (".wasm" if platform == "wasm_eh" else "")
        binary = directory / name
        if not binary.is_file() or binary.is_symlink() or binary.stat().st_size == 0:
            raise ValueError(f"Missing or empty binary: {binary}")
        if set(directory.iterdir()) != {binary}:
            raise ValueError(f"Unexpected files in artifact: {directory}")
        binaries.append((platform, binary))
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError(f"Output must be empty and a directory: {output}")
    output.mkdir(parents=True, exist_ok=True)

    checksums = []
    for platform, binary in binaries:
        name = f"gatekeeper-{tag}-duckdb-v{SUPPORTED_DUCKDB}-{platform}-unsigned.zip"
        archive = output / name
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.write(binary, binary.name)
            for notice in ("LICENSE", "NOTICE"):
                bundle.write(ROOT / notice, notice)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksums.append(f"{digest}  {name}\n")
    (output / "SHA256SUMS").write_text("".join(checksums))
    # The notes lead with this version's CHANGELOG section when it has one (a tag always does; the PR/main
    # packaging check between releases carries the previous release's).
    changes = changelog_sections((ROOT / "CHANGELOG.md").read_text()).get(version, "")
    (output / "RELEASE_NOTES.md").write_text(
        (changes + "\n\n---\n\n" if changes else "") +
        f"These Gatekeeper {version} binaries target **DuckDB {SUPPORTED_DUCKDB}**.\n\n"
        "These are **unsigned development binaries**, built from the workflow's source ref. "
        "They are not DuckDB-signed community binaries. The full distribution matrix "
        "and the Chromium test of its Wasm EH artifact passed before packaging.\n\n"
        "Select the archive matching your DuckDB platform, verify it against `SHA256SUMS`, "
        "and extract it. Each archive includes the canonical extension filename, LICENSE, "
        "and NOTICE. Native builds require explicit unsigned loading; Wasm requires the "
        "pinned EH runtime and unsigned-extension setting. Checksums do not provide "
        "DuckDB signature verification.\n\n"
        f"See [loading instructions](https://github.com/nozzle/duckdb-gatekeeper/blob/{tag}/CONTRIBUTING.md#loading-unsigned-builds), "
        f"[Wasm setup](https://github.com/nozzle/duckdb-gatekeeper/blob/{tag}/test/wasm/README.md), "
        f"and the [security model](https://github.com/nozzle/duckdb-gatekeeper/blob/{tag}/docs/security.md).\n\n"
        "Other DuckDB versions need matching extension builds. Gatekeeper source can be "
        "rebuilt against another engine; compatibility is checked by builds and regression tests, "
        "not an exact-version allowlist or a repeat review of existing function names. "
        "Community submission and deployment are separate from this GitHub Release.\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Release tag, or empty to check packaging on PRs/main")
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    package_release(args.tag, args.artifacts, args.output)


if __name__ == "__main__":
    main()
