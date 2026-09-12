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
    return db.execute("SELECT " + function + "(" + ",".join(arguments) + ")", values).fetchone()[0]


def validate(db, sql, options=None):
    return call(db, "gatekeeper_validate", sql, options)


def configure(db, options=None):
    return call(db, "gatekeeper_configure", options=options)
