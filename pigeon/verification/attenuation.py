"""Attenuation proofs. If narrowing cannot be proven, reject."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pigeon.core.authority import Authority
from pigeon.core.capability import capabilities_subset
from pigeon.core.constraints import constraints_attenuate
from pigeon.core.resource import resources_attenuate
from pigeon.core.result import DelegationError


def assert_attenuates(
    parent: Authority,
    capabilities: Sequence[str],
    resources: Sequence[str],
    constraints: Mapping[str, Any],
) -> None:
    if not capabilities_subset(capabilities, parent.capabilities):
        raise DelegationError(
            "PRIVILEGE_ESCALATION",
            "capability expansion is not permitted",
            {"requested": list(capabilities), "allowed": list(parent.capabilities)},
        )
    if not resources_attenuate(parent.resources, resources):
        raise DelegationError(
            "PRIVILEGE_ESCALATION",
            "resource expansion is not permitted",
            {"requested": list(resources), "allowed": list(parent.resources)},
        )
    ok, details = constraints_attenuate(parent.constraints, constraints)
    if not ok:
        raise DelegationError(
            "PRIVILEGE_ESCALATION",
            "constraint expansion is not permitted",
            details,
        )


def child_attenuates(parent: Authority, child: Authority) -> tuple[bool, dict[str, Any]]:
    if not capabilities_subset(child.capabilities, parent.capabilities):
        return False, {
            "reason": "capability expansion",
            "requested": list(child.capabilities),
            "allowed": list(parent.capabilities),
        }
    if not resources_attenuate(parent.resources, child.resources):
        return False, {
            "reason": "resource expansion",
            "requested": list(child.resources),
            "allowed": list(parent.resources),
        }
    ok, details = constraints_attenuate(parent.constraints, child.constraints)
    if not ok:
        return False, details
    if child.expires_at > parent.expires_at:
        return False, {
            "reason": "child expires after parent",
            "requested": child.expires_at,
            "allowed": parent.expires_at,
        }
    return True, {}
