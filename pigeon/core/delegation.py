"""grant and delegate. A child can never manufacture broader authority."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pigeon.core.authority import (
    Authority,
    default_expiry,
    format_time,
    mint,
    parse_time,
    utcnow,
)
from pigeon.core.capability import capabilities_subset, normalize_capabilities
from pigeon.core.constraints import constraints_attenuate, normalize_constraints
from pigeon.core.principal import Principal
from pigeon.core.resource import normalize_resources, resources_attenuate
from pigeon.core.result import DelegationError
from pigeon.verification.attenuation import assert_attenuates

DEFAULT_MAX_DEPTH = 8
DEFAULT_TTL_SECONDS = 3600


def _as_principal(value: str | Principal) -> Principal:
    if isinstance(value, Principal):
        return value
    if isinstance(value, str) and value:
        return Principal.from_id(value)
    raise DelegationError(
        "MALFORMED_AUTHORITY",
        "subject and issuer must be a principal id or Principal",
    )


def _now(now: str | None):
    if now is None:
        return utcnow()
    return parse_time(now)


def grant(
    subject: str | Principal,
    capabilities: Sequence[str],
    resources: Sequence[str],
    constraints: Mapping[str, Any] | None = None,
    *,
    issuer: str | Principal | None = None,
    expires_at: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: str | None = None,
    authority_id: str | None = None,
    nonce: str | None = None,
) -> Authority:
    issued_dt = _now(now)
    issued_at = format_time(issued_dt)
    expiry = expires_at or format_time(default_expiry(issued_dt, ttl_seconds))
    try:
        parse_time(expiry)
        caps = normalize_capabilities(capabilities)
        res = normalize_resources(resources, is_root=True)
        cons = normalize_constraints(constraints)
        subj = _as_principal(subject)
        iss = (
            _as_principal(issuer)
            if issuer is not None
            else Principal.generate("issuer:root", "organization")
        )
        signing_key = iss.signing_key()
    except DelegationError:
        raise
    except Exception as exc:
        raise DelegationError("MALFORMED_AUTHORITY", str(exc)) from exc
    try:
        return mint(
            issuer=iss,
            subject=subj,
            parent=None,
            capabilities=caps,
            resources=res,
            constraints=cons,
            issued_at=issued_at,
            expires_at=expiry,
            delegation_depth=0,
            signing_key=signing_key,
            authority_id=authority_id,
            nonce=nonce,
        )
    except Exception as exc:
        raise DelegationError("MALFORMED_AUTHORITY", str(exc)) from exc


def delegate(
    parent: Authority,
    subject: str | Principal,
    capabilities: Sequence[str],
    resources: Sequence[str],
    constraints: Mapping[str, Any] | None = None,
    *,
    signing_key: str | None = None,
    expires_at: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: str | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    authority_id: str | None = None,
    nonce: str | None = None,
) -> Authority:
    if not isinstance(parent, Authority):
        raise DelegationError("MALFORMED_AUTHORITY", "parent must be an Authority")
    if not parent.verify_own_signature():
        raise DelegationError("INVALID_SIGNATURE", "parent signature is invalid")
    issued_dt = _now(now)
    issued_at = format_time(issued_dt)
    parent_expires = parse_time(parent.expires_at)
    if parent_expires <= issued_dt:
        raise DelegationError("EXPIRED", "parent authority has expired")
    if expires_at is None:
        child_expires = min(default_expiry(issued_dt, ttl_seconds), parent_expires)
        expiry = format_time(child_expires)
    else:
        expiry = expires_at
        child_expires = parse_time(expiry)
        if child_expires > parent_expires:
            raise DelegationError(
                "PRIVILEGE_ESCALATION",
                "child expires_at must not exceed parent expires_at",
                {"parent": parent.expires_at, "child": expiry},
            )
    if child_expires <= issued_dt:
        raise DelegationError("MALFORMED_AUTHORITY", "child expires_at must be in the future")
    depth = parent.delegation_depth + 1
    if depth > max_depth:
        raise DelegationError(
            "INVALID_DELEGATION",
            f"delegation depth {depth} exceeds maximum {max_depth}",
            {"depth": depth, "max_depth": max_depth},
        )
    try:
        caps = normalize_capabilities(capabilities)
        res = normalize_resources(resources, is_root=False)
        cons = normalize_constraints(constraints)
        subj = _as_principal(subject)
    except DelegationError:
        raise
    except Exception as exc:
        raise DelegationError("MALFORMED_AUTHORITY", str(exc)) from exc
    if not capabilities_subset(caps, parent.capabilities):
        raise DelegationError(
            "PRIVILEGE_ESCALATION",
            "child capabilities must be a subset of parent capabilities",
            {
                "requested": caps,
                "allowed": list(parent.capabilities),
            },
        )
    if not resources_attenuate(parent.resources, res):
        raise DelegationError(
            "PRIVILEGE_ESCALATION",
            "child resources are not provably narrower than parent resources",
            {"requested": res, "allowed": list(parent.resources)},
        )
    ok, details = constraints_attenuate(parent.constraints, cons)
    if not ok:
        raise DelegationError(
            "PRIVILEGE_ESCALATION",
            "child constraints are not provably narrower than parent constraints",
            details,
        )
    assert_attenuates(parent, caps, res, cons)
    try:
        key = signing_key or parent.subject.signing_key()
    except Exception as exc:
        raise DelegationError(
            "INVALID_ISSUER",
            "parent subject private key is required to delegate",
        ) from exc
    try:
        child = mint(
            issuer=parent.subject,
            subject=subj,
            parent=parent.id,
            capabilities=caps,
            resources=res,
            constraints=cons,
            issued_at=issued_at,
            expires_at=expiry,
            delegation_depth=depth,
            signing_key=key,
            ancestors=(parent, *parent._ancestors),
            authority_id=authority_id,
            nonce=nonce,
        )
    except Exception as exc:
        raise DelegationError("MALFORMED_AUTHORITY", str(exc)) from exc
    if child.issuer.public_key != parent.subject.public_key:
        raise DelegationError("INVALID_ISSUER", "child issuer must be the parent subject")
    return child
