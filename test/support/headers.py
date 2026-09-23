"""Name lists read from src/include/function_policy.hpp, the same way for every test that needs one."""
import re

from support.artifact import ROOT

HEADER = ROOT / "src/include/function_policy.hpp"


def header_names(function):
    """The string entries of ``inline const Names &<function>()`` in the header, as a frozenset."""
    body = HEADER.read_text(encoding="utf-8").split(f"inline const Names &{function}()", 1)[1].split("return names;", 1)[0]
    return frozenset(re.findall(r'"([a-z_]+)"', body))


def never_bind_names():
    return header_names("NeverBindFunctions")


def control_plane_names():
    return header_names("ControlPlaneFunctions")
