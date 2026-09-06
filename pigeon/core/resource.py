"""Opaque resource identifiers with a single trailing-wildcard form."""

from __future__ import annotations

from collections.abc import Sequence


def normalize_resources(resources: Sequence[str], *, is_root: bool) -> list[str]:
    if not isinstance(resources, (list, tuple)):
        raise ValueError("resources must be an array of strings")
    seen: set[str] = set()
    out: list[str] = []
    for item in resources:
        if not isinstance(item, str) or item == "":
            raise ValueError("each resource must be a non-empty string")
        if "*" in item[:-1]:
            raise ValueError(
                "only a single trailing '*' wildcard is permitted in a resource"
            )
        if item == "*" and not is_root:
            raise ValueError("'*' as a resource is permitted only in a root grant")
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    out.sort()
    return out


def resource_matches(pattern: str, resource: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return resource.startswith(pattern[:-1])
    return pattern == resource


def any_resource_matches(patterns: Sequence[str], resource: str) -> bool:
    return any(resource_matches(pattern, resource) for pattern in patterns)


def resource_narrower_or_equal(parent: str, child: str) -> bool:
    """True iff every string matching `child` also matches `parent`."""
    if child == "*":
        return parent == "*"
    if parent == "*":
        return True
    if parent == child:
        return True
    if parent.endswith("*"):
        prefix = parent[:-1]
        if child.endswith("*"):
            return child[:-1].startswith(prefix)
        return child.startswith(prefix)
    return False


def resources_attenuate(parent: Sequence[str], child: Sequence[str]) -> bool:
    """Every child pattern must be ⊆ some parent pattern."""
    for child_pat in child:
        if not any(resource_narrower_or_equal(p, child_pat) for p in parent):
            return False
    return True
