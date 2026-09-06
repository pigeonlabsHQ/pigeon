"""Opaque capability strings. Exact match only. No wildcards."""

from __future__ import annotations

from collections.abc import Sequence


def normalize_capabilities(capabilities: Sequence[str]) -> list[str]:
    if not isinstance(capabilities, (list, tuple)):
        raise ValueError("capabilities must be an array of strings")
    seen: set[str] = set()
    out: list[str] = []
    for item in capabilities:
        if not isinstance(item, str) or item == "" or "*" in item:
            raise ValueError(
                "each capability must be a non-empty string without wildcards"
            )
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    out.sort()
    return out


def capabilities_subset(child: Sequence[str], parent: Sequence[str]) -> bool:
    return set(child) <= set(parent)
