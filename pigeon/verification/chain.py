"""Walk and inspect an authority chain."""

from __future__ import annotations

from typing import Any

from pigeon.core.authority import Authority, parse_time
from pigeon.core.result import VerificationResult, deny
from pigeon.verification.attenuation import child_attenuates
from pigeon.verification.revocation import RevocationStore


def assemble_steps(authority: Authority) -> list[dict[str, Any]]:
    steps = []
    for i, link in enumerate(authority.chain()):
        steps.append(
            {
                "index": i,
                "id": link.id,
                "issuer": link.issuer.principal_id,
                "subject": link.subject.principal_id,
                "parent": link.parent,
                "delegation_depth": link.delegation_depth,
                "capabilities": list(link.capabilities),
                "resources": list(link.resources),
                "expires_at": link.expires_at,
            }
        )
    return steps


def structural_chain_error(
    authority: Authority,
    *,
    now,
    max_depth: int,
    revocation_store: RevocationStore,
) -> VerificationResult | None:
    chain = authority.chain()
    if len(chain) - 1 > max_depth or authority.delegation_depth > max_depth:
        return deny(
            "INVALID_DELEGATION",
            "delegation depth exceeds maximum",
            details={
                "depth": authority.delegation_depth,
                "max_depth": max_depth,
            },
        )
    for i, link in enumerate(chain):
        if revocation_store.is_revoked(link.id):
            return deny(
                "REVOKED",
                "an authority in the chain has been revoked",
                details={"authority_id": link.id, "index": i},
                steps=tuple(assemble_steps(authority)),
            )
        try:
            if parse_time(link.expires_at) <= now:
                return deny(
                    "EXPIRED",
                    "an authority in the chain has expired",
                    details={"authority_id": link.id, "expires_at": link.expires_at},
                    steps=tuple(assemble_steps(authority)),
                )
        except ValueError as exc:
            return deny("MALFORMED_AUTHORITY", str(exc), details={"authority_id": link.id})
        if not link.verify_own_signature():
            return deny(
                "INVALID_SIGNATURE",
                "signature verification failed",
                details={"authority_id": link.id, "index": i},
                steps=tuple(assemble_steps(authority)),
            )
    if authority.parent is not None and not authority._ancestors:
        return deny(
            "INVALID_PARENT",
            "delegated authority is missing its parent chain",
            details={"parent": authority.parent},
        )
    if authority.parent is None and authority._ancestors:
        return deny(
            "INVALID_PARENT",
            "root authority must not carry ancestors",
            details={"id": authority.id},
        )
    # Walk leaf -> root checking parent links. chain[i].parent == chain[i+1].id
    for i in range(len(chain) - 1):
        child, parent = chain[i], chain[i + 1]
        if child.parent != parent.id:
            return deny(
                "INVALID_PARENT",
                "parent id does not match the next chain link",
                details={
                    "child_id": child.id,
                    "child_parent": child.parent,
                    "expected_parent_id": parent.id,
                },
                steps=tuple(assemble_steps(authority)),
            )
        if child.delegation_depth != parent.delegation_depth + 1:
            return deny(
                "INVALID_DELEGATION",
                "delegation_depth must be parent depth plus one",
                details={
                    "child_depth": child.delegation_depth,
                    "parent_depth": parent.delegation_depth,
                },
            )
        if not child.issuer.identity_matches(parent.subject):
            return deny(
                "INVALID_ISSUER",
                "child issuer must be the parent subject",
                details={
                    "issuer": child.issuer.to_dict(),
                    "parent_subject": parent.subject.to_dict(),
                },
            )
        ok, details = child_attenuates(parent, child)
        if not ok:
            return deny(
                "PRIVILEGE_ESCALATION",
                "a chain link expands authority relative to its parent",
                details=details,
                steps=tuple(assemble_steps(authority)),
            )
    root = chain[-1]
    if root.parent is not None or root.delegation_depth != 0:
        return deny(
            "INVALID_PARENT",
            "chain does not terminate at a root grant",
            details={"root_id": root.id, "root_parent": root.parent},
        )
    return None
