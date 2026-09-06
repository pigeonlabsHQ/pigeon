"""Closed constraint primitive set. Fail closed if narrowing cannot be proven."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from pigeon.crypto.canonicalization import MAX_SAFE_INT, MIN_SAFE_INT

OPS = frozenset(
    {"eq", "neq", "max", "min", "in", "prefix", "suffix", "rate", "count"}
)
STATEFUL_OPS = frozenset({"rate", "count"})

_RATE_KEY = re.compile(
    r"^(?:max_)?([A-Za-z_][A-Za-z0-9_]*)_per_(seconds?|minutes?|hours?|days?)$"
)
_MAX_KEY = re.compile(r"^max_([A-Za-z_][A-Za-z0-9_]*)$")
_MIN_KEY = re.compile(r"^min_([A-Za-z_][A-Za-z0-9_]*)$")

_WINDOW = {
    "second": 1,
    "seconds": 1,
    "minute": 60,
    "minutes": 60,
    "hour": 3600,
    "hours": 3600,
    "day": 86400,
    "days": 86400,
}


def _require_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if value < MIN_SAFE_INT or value > MAX_SAFE_INT:
        raise ValueError(f"{field} is outside the safe integer range")
    return value


def _require_positive_int(value: Any, field: str) -> int:
    n = _require_int(value, field)
    if n <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return n


def _values_equal(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    return a == b


def normalize_constraints(constraints: Mapping[str, Any] | None) -> dict[str, Any]:
    if constraints is None:
        return {}
    if not isinstance(constraints, dict):
        raise ValueError("constraints must be an object")
    out: dict[str, Any] = {}
    for key, raw in constraints.items():
        if not isinstance(key, str) or key == "":
            raise ValueError("constraint dimension names must be non-empty strings")
        expr, dimension = _expand_one(key, raw)
        _validate_expr(expr)
        if dimension in out:
            raise ValueError(f"duplicate constraint dimension {dimension}")
        out[dimension] = expr
    return {k: out[k] for k in sorted(out)}


def _expand_one(key: str, raw: Any) -> tuple[dict[str, Any], str]:
    if isinstance(raw, dict):
        if "op" not in raw:
            raise ValueError(f"constraint {key} is missing op")
        extra = set(raw) - _allowed_fields(raw["op"])
        if extra:
            raise ValueError(
                f"constraint {key} has unknown fields: {sorted(extra)}"
            )
        return dict(raw), key
    if isinstance(raw, bool) or raw is None:
        return {"op": "eq", "value": raw}, key
    if isinstance(raw, int):
        match = _RATE_KEY.match(key)
        if match:
            return (
                {
                    "op": "rate",
                    "max": _require_positive_int(raw, key),
                    "window_seconds": _WINDOW[match.group(2)],
                },
                match.group(1),
            )
        match = _MAX_KEY.match(key)
        if match:
            return {"op": "max", "value": _require_int(raw, key)}, match.group(1)
        match = _MIN_KEY.match(key)
        if match:
            return {"op": "min", "value": _require_int(raw, key)}, match.group(1)
        return {"op": "max", "value": _require_int(raw, key)}, key
    if isinstance(raw, str):
        return {"op": "eq", "value": raw}, key
    if isinstance(raw, list):
        return {"op": "in", "values": list(raw)}, key
    raise ValueError(f"unsupported constraint value for {key}")


def _allowed_fields(op: Any) -> set[str]:
    if op in {"eq", "neq", "max", "min", "prefix", "suffix"}:
        return {"op", "value"}
    if op == "in":
        return {"op", "values"}
    if op == "rate":
        return {"op", "max", "window_seconds"}
    if op == "count":
        return {"op", "max"}
    return {"op"}


def _validate_expr(expr: dict[str, Any]) -> None:
    op = expr.get("op")
    if op not in OPS:
        raise ValueError(f"unknown constraint op {op!r}")
    extra = set(expr) - _allowed_fields(op)
    if extra:
        raise ValueError(f"constraint has unknown fields: {sorted(extra)}")
    if op in {"eq", "neq"}:
        _validate_scalar(expr.get("value"), "value")
    elif op in {"max", "min"}:
        _require_int(expr.get("value"), "value")
    elif op == "in":
        values = expr.get("values")
        if not isinstance(values, list) or not values:
            raise ValueError("in.values must be a non-empty array")
        for item in values:
            _validate_scalar(item, "values item")
        expr["values"] = sorted(values, key=_sort_key)
    elif op in {"prefix", "suffix"}:
        value = expr.get("value")
        if not isinstance(value, str) or value == "":
            raise ValueError(f"{op}.value must be a non-empty string")
    elif op == "rate":
        _require_positive_int(expr.get("max"), "max")
        _require_positive_int(expr.get("window_seconds"), "window_seconds")
    elif op == "count":
        _require_positive_int(expr.get("max"), "max")


def _validate_scalar(value: Any, field: str) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        _require_int(value, field)
        return
    raise ValueError(f"{field} must be a string, integer, boolean, or null")


def _sort_key(value: Any) -> tuple:
    if value is None:
        return (0, "")
    if isinstance(value, bool):
        return (1, int(value))
    if isinstance(value, int):
        return (2, value)
    return (3, value)


def constraints_attenuate(
    parent: Mapping[str, Any], child: Mapping[str, Any]
) -> tuple[bool, dict[str, Any]]:
    """Every parent dimension must exist in child and be provably narrower or equal.

    Extra child dimensions are allowed (they only narrow). If narrowing cannot
    be proven, return False. Never guess.
    """
    for dim, parent_expr in parent.items():
        if dim not in child:
            return False, {
                "dimension": dim,
                "reason": "parent constraint removed",
                "parent": parent_expr,
            }
        if not _expr_narrower_or_equal(parent_expr, child[dim]):
            return False, {
                "dimension": dim,
                "reason": "child constraint is not provably narrower",
                "parent": parent_expr,
                "child": child[dim],
            }
    return True, {}


def _expr_narrower_or_equal(parent: dict[str, Any], child: dict[str, Any]) -> bool:
    pop, cop = parent["op"], child["op"]
    if pop != cop:
        return _cross_op_narrower(parent, child)
    if pop == "eq":
        return _values_equal(parent["value"], child["value"])
    if pop == "neq":
        return _values_equal(parent["value"], child["value"])
    if pop == "max":
        return child["value"] <= parent["value"]
    if pop == "min":
        return child["value"] >= parent["value"]
    if pop == "in":
        return set(_freeze(v) for v in child["values"]) <= set(
            _freeze(v) for v in parent["values"]
        )
    if pop == "prefix":
        return child["value"].startswith(parent["value"])
    if pop == "suffix":
        return child["value"].endswith(parent["value"])
    if pop == "rate":
        return (
            child["window_seconds"] == parent["window_seconds"]
            and child["max"] <= parent["max"]
        )
    if pop == "count":
        return child["max"] <= parent["max"]
    return False


def _cross_op_narrower(parent: dict[str, Any], child: dict[str, Any]) -> bool:
    pop, cop = parent["op"], child["op"]
    if pop == "neq" and cop == "eq":
        return not _values_equal(child["value"], parent["value"])
    if pop == "in" and cop == "eq":
        return any(_values_equal(child["value"], v) for v in parent["values"])
    if pop == "prefix" and cop == "eq":
        return isinstance(child["value"], str) and child["value"].startswith(
            parent["value"]
        )
    if pop == "suffix" and cop == "eq":
        return isinstance(child["value"], str) and child["value"].endswith(
            parent["value"]
        )
    if pop == "max" and cop == "eq":
        return isinstance(child["value"], int) and not isinstance(
            child["value"], bool
        ) and child["value"] <= parent["value"]
    if pop == "min" and cop == "eq":
        return isinstance(child["value"], int) and not isinstance(
            child["value"], bool
        ) and child["value"] >= parent["value"]
    if pop == "in" and cop == "in":
        return False
    return False


def _freeze(value: Any) -> Any:
    if isinstance(value, bool):
        return ("bool", value)
    return ("val", value)


def evaluate_stateless(
    constraints: Mapping[str, Any], context: Mapping[str, Any]
) -> tuple[str | None, str, dict[str, Any]]:
    """Return (reason_code, message, details) or (None, "", {}) if ok."""
    for dim, expr in constraints.items():
        op = expr["op"]
        if op in STATEFUL_OPS:
            continue
        actual = context.get(dim, _MISSING)
        ok, details = _eval_one(dim, expr, actual)
        if not ok:
            return (
                "CONSTRAINT_VIOLATION",
                f"constraint {dim} ({op}) failed",
                details,
            )
    return None, "", {}


_MISSING = object()


def _eval_one(
    dim: str, expr: dict[str, Any], actual: Any
) -> tuple[bool, dict[str, Any]]:
    op = expr["op"]
    details = {
        "dimension": dim,
        "op": op,
        "allowed": expr,
        "requested": None if actual is _MISSING else actual,
    }
    if actual is _MISSING:
        return False, details
    if op == "eq":
        return _values_equal(actual, expr["value"]), details
    if op == "neq":
        return not _values_equal(actual, expr["value"]), details
    if op == "max":
        if isinstance(actual, bool) or not isinstance(actual, int):
            return False, details
        return actual <= expr["value"], details
    if op == "min":
        if isinstance(actual, bool) or not isinstance(actual, int):
            return False, details
        return actual >= expr["value"], details
    if op == "in":
        return any(_values_equal(actual, v) for v in expr["values"]), details
    if op == "prefix":
        return isinstance(actual, str) and actual.startswith(expr["value"]), details
    if op == "suffix":
        return isinstance(actual, str) and actual.endswith(expr["value"]), details
    return False, details


def increment_for(expr: dict[str, Any], dimension: str, context: Mapping[str, Any]) -> int:
    raw = context.get(dimension, 1)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        raise ValueError("increment must be a positive integer")
    return raw
