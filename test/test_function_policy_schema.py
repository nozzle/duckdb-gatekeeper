"""Source-only policy schema checks, independent of an installed extension."""
import json
from pathlib import Path

import jsonschema
import pytest

SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "docs/policy-v2.schema.json").read_text())


@pytest.mark.parametrize("entry,valid", [
    ({"schema_path":["main"],"name":"abs"}, True),
    ({"catalog":None,"schema_path":["finance","*"],"name":"*","type":"ScAlAr"}, True),
    ({"schema_path":["main"],"name":"f","type":None}, True),
    ({"schema_path":["main"],"name":"f","type":"window"}, True),
    ("abs", False),
    ({"name":"abs"}, False),
    ({"schema_path":[],"name":"abs"}, False),
    ({"schema_path":["main"],"name":"abs","type":"pragma"}, False),
    ({"schema_path":["main"],"name":"abs","type":""}, False),
    ({"schema_path":["main"],"name":"abs","type":"scalar\n"}, False),
    ({"schema_path":["main"],"name":"abs\0"}, False),
    ({"schema_path":["main"],"name":"abs","extra":True}, False),
])
def test_function_grant_schema(entry, valid):
    validator = jsonschema.Draft202012Validator(SCHEMA)
    assert validator.is_valid({"version":2,"options":{"allowed_functions":[entry]}}) is valid
