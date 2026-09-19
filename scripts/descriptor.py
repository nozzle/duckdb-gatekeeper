"""Reads community/description.yml without a YAML dependency.

The descriptor is written in canonical two-space YAML: top-level sections, unquoted plain scalars for the pins
the release tooling checks, and a literal block scalar (``key: |``) for docs.hello_world. Anything else is layout
drift, which is rejected rather than guessed at.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def text(root=ROOT):
    return (root / "community/description.yml").read_text()


class DescriptorError(ValueError):
    pass


def _entry(section_name, key, value_pattern, descriptor, shape):
    """The match of ``key`` inside the body of top-level ``section_name:``; the error names the missing
    ``section.key`` whichever of the two is absent."""
    location = f"community/description.yml {section_name}.{key}"
    section = re.search(rf"(?m)^{re.escape(section_name)}:[ \t]*\n((?:[ \t]+[^\n]*\n|\n)*)", descriptor)
    match = section and re.search(rf"(?m)^  {re.escape(key)}:{value_pattern}", section.group(1))
    if not match:
        raise DescriptorError(f"Cannot read {location}: expected {shape}")
    return match


def scalar(section_name, key, descriptor=None):
    """The plain scalar at ``section_name.key`` (two-space indented, unquoted, optional trailing comment)."""
    match = _entry(section_name, key, r"[ \t]*([^\s#\"']+)[ \t]*(?:#.*)?$", text() if descriptor is None else descriptor,
                   "an unquoted plain scalar")
    return match.group(1)


def block_scalar(section_name, key, descriptor=None):
    """The lines of the literal block scalar at ``section_name.key`` (``key: |``), dedented by its four-space
    indent; blank lines are kept."""
    match = _entry(section_name, key, r" \|\n((?:    [^\n]*\n|\n)*)", text() if descriptor is None else descriptor,
                   "a two-space indented block scalar")
    return [line[4:] if line.startswith("    ") else line.strip() for line in match.group(1).splitlines()]
