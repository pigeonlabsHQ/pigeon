"""Canonical JSON for Pigeon Pass signing.

This module implements SPEC.md "Canonical serialization" exactly.
A future implementation must produce identical bytes from that document
alone; this file is the reference, not the specification.
"""

from __future__ import annotations

from typing import Any

MAX_SAFE_INT = (1 << 53) - 1
MIN_SAFE_INT = -MAX_SAFE_INT

_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}


class CanonicalError(ValueError):
    """Signed payload cannot be canonicalized."""


def canonicalize(value: Any) -> bytes:
    """Return UTF-8 canonical JSON bytes for `value`."""
    return _serialize(value).encode("utf-8")


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if value < MIN_SAFE_INT or value > MAX_SAFE_INT:
            raise CanonicalError(
                f"integer {value} is outside the safe JSON integer range"
            )
        if value == 0:
            return "0"
        return str(value)
    if isinstance(value, float):
        raise CanonicalError("floating-point numbers are not permitted")
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalError("object keys must be strings")
        parts = []
        for key in sorted(value.keys()):
            parts.append(_serialize_string(key) + ":" + _serialize(value[key]))
        return "{" + ",".join(parts) + "}"
    raise CanonicalError(f"unsupported type {type(value).__name__}")


def _serialize_string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[code])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)
