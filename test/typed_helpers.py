import re
from pathlib import Path


def never_bind_names():
    header = (Path(__file__).resolve().parents[1] / "src/include/function_policy.hpp").read_text()
    return re.findall(r'"([a-z_]+)"', header.split("static const Names names =", 1)[1].split("return names;", 1)[0])


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
    return call(db, "gatekeeper_validate", sql, options)


def configure(db, options=None):
    return call(db, "gatekeeper_configure", options=options)
