"""Dependency-free validator for inventories/schema.json.

Community distribution builds run scripts/generate.py with only the Python standard library, so
inventory validation cannot import jsonschema. This module evaluates exactly the JSON Schema
2020-12 keywords the inventory schema uses and raises SchemaError on any keyword it does not
implement, so a schema edit that needs a new keyword fails loudly instead of silently passing.
The test suite cross-checks this validator against the jsonschema package on the real inventories
and on mutated documents.
"""
import json
import re

TYPES = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float), "boolean": bool}
KNOWN = {"$schema", "$id", "title", "description", "$defs", "type", "properties", "required", "additionalProperties",
         "pattern", "minLength", "minItems", "minProperties", "uniqueItems", "items", "$ref", "allOf", "if", "then",
         "else", "not", "const"}


class SchemaError(ValueError):
    """The schema uses a keyword this validator does not implement."""


class ValidationError(ValueError):
    def __init__(self, path, message):
        self.path = list(path)
        self.message = message
        super().__init__(message)


def _scan(schema):
    """Reject unsupported keywords anywhere in the schema, including $defs and unselected branches."""
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise SchemaError("schema nodes must be objects or booleans")
    unknown = set(schema) - KNOWN
    if unknown:
        raise SchemaError("unsupported schema keywords: " + ", ".join(sorted(unknown)))
    if "$ref" in schema and not schema["$ref"].startswith("#/"):
        raise SchemaError("only local $ref pointers are supported: " + schema["$ref"])
    if "type" in schema and schema["type"] not in TYPES:
        raise SchemaError("unsupported type: " + str(schema["type"]))
    for key in ("properties", "$defs"):
        for sub in schema.get(key, {}).values():
            _scan(sub)
    for key in ("additionalProperties", "items", "if", "then", "else", "not"):
        if key in schema:
            _scan(schema[key])
    for sub in schema.get("allOf", []):
        _scan(sub)


def _resolve(root, ref):
    if not ref.startswith("#/"):
        raise SchemaError("only local $ref pointers are supported: " + ref)
    node = root
    for part in ref[2:].split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def _matches(root, schema, value, path):
    try:
        _check(root, schema, value, path)
    except ValidationError:
        return False
    return True


def _check(root, schema, value, path):
    if schema is True:
        return
    if schema is False:
        raise ValidationError(path, "value is not allowed")
    unknown = set(schema) - KNOWN
    if unknown:
        raise SchemaError("unsupported schema keywords: " + ", ".join(sorted(unknown)))
    if "$ref" in schema:
        _check(root, _resolve(root, schema["$ref"]), value, path)
    if "type" in schema:
        expected = TYPES[schema["type"]]
        if not isinstance(value, expected) or (schema["type"] in ("integer", "number") and isinstance(value, bool)):
            raise ValidationError(path, f"{json.dumps(value)[:40]} is not of type '{schema['type']}'")
    if "const" in schema and value != schema["const"]:
        raise ValidationError(path, f"{json.dumps(schema['const'])} was expected")
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            raise ValidationError(path, f"{json.dumps(value)} does not match {json.dumps(schema['pattern'])}")
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ValidationError(path, f"{json.dumps(value)} is too short")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise ValidationError(path, f"{json.dumps(value)[:40]} is too short")
        if schema.get("uniqueItems"):
            seen = []
            for item in value:
                if item in seen:
                    raise ValidationError(path, f"{json.dumps(value)[:40]} has non-unique elements")
                seen.append(item)
        if "items" in schema:
            for index, item in enumerate(value):
                _check(root, schema["items"], item, path + [index])
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                raise ValidationError(path, f"'{key}' is a required property")
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            raise ValidationError(path, "object does not have enough properties")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                _check(root, properties[key], item, path + [key])
            elif "additionalProperties" in schema:
                if schema["additionalProperties"] is False:
                    raise ValidationError(path, f"Additional properties are not allowed ('{key}' was unexpected)")
                _check(root, schema["additionalProperties"], item, path + [key])
    for sub in schema.get("allOf", []):
        _check(root, sub, value, path)
    if "if" in schema:
        branch = "then" if _matches(root, schema["if"], value, path) else "else"
        if branch in schema:
            _check(root, schema[branch], value, path)
    if "not" in schema and _matches(root, schema["not"], value, path):
        raise ValidationError(path, "value should not be valid under the 'not' schema")


def validate(schema, value):
    """Raise ValidationError for the first violation, or SchemaError for an unsupported schema.

    The whole schema is scanned for unsupported keywords before any document is evaluated, so a
    keyword hidden in an unreferenced definition or an unselected conditional branch still fails.
    """
    _scan(schema)
    _check(schema, schema, value, [])
