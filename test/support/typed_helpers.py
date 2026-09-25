"""Gatekeeper's SQL surface through its typed, named-parameter API."""
import re


def call(db, function, sql=None, options=None):
    arguments, values = [], []
    if function == "gatekeeper_validate":
        arguments.append("?")
        values.append(sql)
    for key, value in (options or {}).items():
        if not re.fullmatch(r"[a-z_]+", key):
            raise ValueError("invalid test option name")
        arguments.append(key + " := ?")
        values.append(value)
    prefix = "CALL " if function == "gatekeeper_configure" else "SELECT * FROM "
    result = db.execute(prefix + function + "(" + ",".join(arguments) + ")", values)
    if function == "gatekeeper_configure":
        return result.fetchone()[0]
    return dict(zip((column[0] for column in result.description), result.fetchone()))


def validate(db, sql, options=None):
    """The gatekeeper_validate row for ``sql`` under the request-layer ``options``, as a dict."""
    return call(db, "gatekeeper_validate", sql, options)


def configure(db, options=None):
    """Replace the global policy; no options restores the defaults."""
    return call(db, "gatekeeper_configure", options=options)


def policy(db):
    """The canonical global policy as the setting reports it."""
    return db.execute("SELECT current_setting('gatekeeper_policy')").fetchone()[0]


def rule(catalog="*", schema_path=("*",), table="*"):
    """A table rule for allowed_tables or blocked_tables."""
    return {"catalog": catalog, "schema_path": list(schema_path), "table": table}


def grants(*names, catalog=None, schema_path=("*",), type=None):
    """Explicit structured grants for tests; never converts API inputs implicitly."""
    return [{"catalog": catalog, "schema_path": list(schema_path), "name": name, "type": type} for name in names]
