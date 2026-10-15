"""Reads community/description.yml without a YAML dependency.

The descriptor is written in canonical two-space YAML: top-level sections, unquoted plain scalars for the pins
the release tooling checks, and a literal block scalar (``key: |``) for docs.hello_world. Anything else is layout
drift, which is rejected rather than guessed at.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def text(root=ROOT):
    return (root / "community/description.yml").read_text(encoding="utf-8")


class DescriptorError(ValueError):
    pass


def _section(section_name, descriptor):
    """The indented body of top-level ``section_name:``, or None when the descriptor has no such section."""
    section = re.search(rf"(?m)^{re.escape(section_name)}:[ \t]*\n((?:[ \t]+[^\n]*\n|\n)*)", descriptor)
    return section.group(1) if section else None


def _spellings(body, key):
    """Every line of ``body`` that writes ``key`` as a mapping key, canonical or not: any indentation, quoted or not,
    whitespace before the colon or not."""
    return [match.group(0) for match in re.finditer(rf"(?m)^[ \t]*([\"']?){re.escape(key)}\1[ \t]*:", body)]


def _entry(section_name, key, value_pattern, descriptor, shape):
    """The match of ``key`` inside the body of top-level ``section_name:``; the error names the missing
    ``section.key`` whichever of the two is absent. The key must be written once, two-space indented and unquoted:
    another spelling, or a repeat a YAML reader would let override the first, is drift."""
    location = f"community/description.yml {section_name}.{key}"
    body = _section(section_name, descriptor)
    if body is not None and _spellings(body, key) not in ([], [f"  {key}:"]):
        raise DescriptorError(f"Cannot read {location}: expected the key once, two-space indented and unquoted")
    match = body is not None and re.search(rf"(?m)^  {re.escape(key)}:{value_pattern}", body)
    if not match:
        raise DescriptorError(f"Cannot read {location}: expected {shape}")
    return match


def scalar(section_name, key, descriptor=None):
    """The plain scalar at ``section_name.key`` (two-space indented, unquoted, optional trailing comment)."""
    match = _entry(section_name, key, r"[ \t]*([^\s#\"']+)[ \t]*(?:#.*)?$", text() if descriptor is None else descriptor,
                   "an unquoted plain scalar")
    return match.group(1)


def has_key(section_name, key, descriptor=None):
    """Whether top-level ``section_name:`` has ``key``, whatever its value's layout. The key written in any spelling
    counts as present, so a non-canonical one raises as drift rather than reading as absent."""
    descriptor = text() if descriptor is None else descriptor
    body = _section(section_name, descriptor)
    if body is None or not _spellings(body, key):
        return False
    _entry(section_name, key, "", descriptor, "a key")
    return True


def optional_scalar(section_name, key, descriptor=None):
    """The plain scalar at ``section_name.key``, or None when the key is absent. A key that is present with any other
    layout is drift and raises, as for ``scalar``; it is never mistaken for an absent one."""
    descriptor = text() if descriptor is None else descriptor
    return scalar(section_name, key, descriptor) if has_key(section_name, key, descriptor) else None


def block_scalar(section_name, key, descriptor=None):
    """The lines of the literal block scalar at ``section_name.key`` (``key: |``), dedented by its four-space
    indent; blank lines are kept."""
    match = _entry(section_name, key, r" \|\n((?:    [^\n]*\n|\n)*)", text() if descriptor is None else descriptor,
                   "a two-space indented block scalar")
    return [line[4:] if line.startswith("    ") else line.strip() for line in match.group(1).splitlines()]
