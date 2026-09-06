"""Security and protocol tests required for v0.1."""

from __future__ import annotations

import copy

import pytest

from pigeon import (
    Authority,
    DelegationError,
    MemoryReplayStore,
    MemoryRevocationStore,
    Principal,
    delegate,
    grant,
    verify,
)
from pigeon.core.authority import mint
from pigeon.verification.usage import MemoryUsageStore

NOW = "2026-09-06T12:00:00Z"
LATER = "2026-09-06T13:00:00Z"
EXPIRED = "2026-09-06T11:00:00Z"


def _root(**kwargs):
    defaults = dict(
        subject="agent:deploy",
        capabilities=["deploy"],
        resources=["environment:staging"],
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
    )
    defaults.update(kwargs)
    return grant(**defaults)


def test_valid_signature_allows():
    auth = _root()
    result = verify(auth, "deploy", "environment:staging", now=NOW)
    assert result.allowed
    assert result.reason_code is None
    assert result.steps


def test_invalid_signature_denied():
    auth = _root()
    broken = auth.to_dict()
    broken["signature"] = "A" * 86
    parsed = Authority.from_dict(broken)
    result = verify(parsed, "deploy", "environment:staging", now=NOW)
    assert result.allowed is False
    assert result.reason_code == "INVALID_SIGNATURE"


def test_tamper_every_signed_field():
    auth = _root(constraints={"region": {"op": "eq", "value": "eu"}})
    other = Principal.generate("agent:other")
    replacements = {
        "id": "00000000-0000-0000-0000-000000000000",
        "version": 1,  # unchanged value still re-checked via other fields; skip
        "issuer": other.to_dict(),
        "subject": other.to_dict(),
        "parent": "not-a-real-parent",
        "capabilities": ["deploy", "write"],
        "resources": ["environment:production"],
        "constraints": {"region": {"op": "eq", "value": "us"}},
        "issued_at": "2026-09-05T12:00:00Z",
        "expires_at": "2026-09-08T12:00:00Z",
        "nonce": "ff" * 16,
        "delegation_depth": 3,
    }
    for field, value in replacements.items():
        if field == "version":
            continue
        data = auth.to_dict()
        data[field] = value
        parsed = Authority.from_dict(data)
        result = verify(parsed, "deploy", "environment:staging", now=NOW)
        assert result.allowed is False, field
        assert result.reason_code in {
            "INVALID_SIGNATURE",
            "INVALID_PARENT",
            "INVALID_DELEGATION",
            "MALFORMED_AUTHORITY",
        }, (field, result.reason_code)


def test_tamper_version_rejected():
    data = _root().to_dict()
    data["version"] = 2
    with pytest.raises(ValueError):
        Authority.from_dict(data)


def test_expiration():
    auth = _root()
    result = verify(auth, "deploy", "environment:staging", now="2026-09-08T12:00:00Z")
    assert result.allowed is False
    assert result.reason_code == "EXPIRED"


def test_invalid_issuer():
    parent = _root()
    child = delegate(
        parent,
        "agent:runner",
        ["deploy"],
        ["environment:staging"],
        now=NOW,
    )
    attacker = Principal.generate("agent:attacker")
    forged = mint(
        issuer=attacker,
        subject=child.subject,
        parent=parent.id,
        capabilities=child.capabilities,
        resources=child.resources,
        constraints=child.constraints,
        issued_at=child.issued_at,
        expires_at=child.expires_at,
        delegation_depth=1,
        signing_key=attacker.signing_key(),
        ancestors=child._ancestors,
        authority_id=child.id,
        nonce=child.nonce,
    )
    result = verify(forged, "deploy", "environment:staging", now=NOW)
    assert result.allowed is False
    assert result.reason_code == "INVALID_ISSUER"


def test_invalid_parent_missing_chain():
    parent = _root()
    child = delegate(
        parent, "agent:runner", ["deploy"], ["environment:staging"], now=NOW
    )
    orphan = child.with_ancestors(())
    result = verify(orphan, "deploy", "environment:staging", now=NOW)
    assert result.reason_code in {"INVALID_PARENT", "MALFORMED_AUTHORITY"}


def test_valid_and_narrowed_delegation():
    parent = _root(resources=["environment:*"])
    child = delegate(
        parent,
        "agent:runner",
        ["deploy"],
        ["environment:staging"],
        now=NOW,
    )
    assert child.parent == parent.id
    assert child.delegation_depth == 1
    ok = verify(child, "deploy", "environment:staging", now=NOW)
    assert ok.allowed
    denied = verify(child, "deploy", "environment:production", now=NOW)
    assert denied.reason_code == "RESOURCE_NOT_ALLOWED"


def test_capability_expansion_and_injection():
    parent = grant(
        "agent:reader",
        ["read"],
        ["database:customers"],
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
    )
    with pytest.raises(DelegationError) as exc:
        delegate(parent, "agent:child", ["read", "write"], ["database:customers"], now=NOW)
    assert exc.value.reason_code == "PRIVILEGE_ESCALATION"
    with pytest.raises(DelegationError) as exc:
        delegate(parent, "agent:child", ["write"], ["database:customers"], now=NOW)
    assert exc.value.reason_code == "PRIVILEGE_ESCALATION"


def test_resource_expansion():
    parent = _root(resources=["environment:staging"])
    with pytest.raises(DelegationError) as exc:
        delegate(parent, "agent:child", ["deploy"], ["environment:*"], now=NOW)
    assert exc.value.reason_code == "PRIVILEGE_ESCALATION"
    with pytest.raises(DelegationError) as exc:
        delegate(
            parent, "agent:child", ["deploy"], ["environment:production"], now=NOW
        )
    assert exc.value.reason_code == "PRIVILEGE_ESCALATION"


def test_constraint_expansion():
    parent = grant(
        "agent:shop",
        ["purchase"],
        ["merchant:*"],
        {"amount": 50},
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
    )
    with pytest.raises(DelegationError) as exc:
        delegate(
            parent,
            "agent:child",
            ["purchase"],
            ["merchant:books"],
            {"amount": 100},
            now=NOW,
        )
    assert exc.value.reason_code == "PRIVILEGE_ESCALATION"
    child = delegate(
        parent,
        "agent:child",
        ["purchase"],
        ["merchant:books"],
        {"amount": 20, "currency": {"op": "eq", "value": "EUR"}},
        now=NOW,
    )
    assert child.constraints["amount"]["value"] == 20


def test_rate_limit_enforcement():
    auth = _root(constraints={"max_deploys_per_hour": 2})
    usage = MemoryUsageStore()
    replay = MemoryReplayStore()
    rev = MemoryRevocationStore()
    kwargs = dict(
        usage_store=usage,
        replay_store=replay,
        revocation_store=rev,
        now=NOW,
    )
    assert verify(auth, "deploy", "environment:staging", **kwargs).allowed
    assert verify(auth, "deploy", "environment:staging", **kwargs).allowed
    denied = verify(auth, "deploy", "environment:staging", **kwargs)
    assert denied.allowed is False
    assert denied.reason_code == "RATE_LIMIT_EXCEEDED"
    assert denied.details["allowed"] == 2
    assert denied.details["requested"] == 3


def test_count_limit_enforcement():
    auth = grant(
        "agent:shop",
        ["purchase"],
        ["merchant:books"],
        {"amount": {"op": "count", "max": 100}},
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
    )
    usage = MemoryUsageStore()
    kwargs = dict(
        usage_store=usage,
        replay_store=MemoryReplayStore(),
        revocation_store=MemoryRevocationStore(),
        now=NOW,
    )
    assert verify(
        auth, "purchase", "merchant:books", {"amount": 60}, **kwargs
    ).allowed
    denied = verify(
        auth, "purchase", "merchant:books", {"amount": 50}, **kwargs
    )
    assert denied.reason_code == "CONSTRAINT_VIOLATION"
    assert denied.details["allowed"] == 100
    assert denied.details["requested"] == 110


def test_subject_substitution():
    parent = _root()
    attacker = Principal.generate("agent:attacker")
    child = delegate(
        parent, "agent:runner", ["deploy"], ["environment:staging"], now=NOW
    )
    data = child.to_dict()
    data["subject"] = attacker.to_dict()
    parsed = Authority.from_dict(data).with_ancestors(child._ancestors)
    result = verify(parsed, "deploy", "environment:staging", now=NOW)
    assert result.reason_code == "INVALID_SIGNATURE"


def test_parent_substitution():
    parent = _root()
    other = grant(
        "agent:unrelated",
        ["deploy"],
        ["environment:staging"],
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
    )
    child = delegate(
        parent, "agent:runner", ["deploy"], ["environment:staging"], now=NOW
    )
    swapped = child.with_ancestors((other,))
    result = verify(swapped, "deploy", "environment:staging", now=NOW)
    assert result.allowed is False
    assert result.reason_code in {"INVALID_PARENT", "INVALID_ISSUER"}


def test_chain_manipulation_drop_parent():
    root = grant(
        "agent:a",
        ["read"],
        ["database:*"],
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
    )
    mid = delegate(root, "agent:b", ["read"], ["database:customers"], now=NOW)
    leaf = delegate(mid, "agent:c", ["read"], ["database:customers"], now=NOW)
    skipped = leaf.with_ancestors((root,))
    result = verify(skipped, "read", "database:customers", now=NOW)
    assert result.allowed is False
    assert result.reason_code in {"INVALID_PARENT", "INVALID_ISSUER"}


def test_depth_limits():
    auth = grant(
        "agent:0",
        ["execute"],
        ["mcp:tool"],
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
    )
    for i in range(2):
        auth = delegate(
            auth, f"agent:{i+1}", ["execute"], ["mcp:tool"], now=NOW, max_depth=2
        )
    with pytest.raises(DelegationError) as exc:
        delegate(auth, "agent:3", ["execute"], ["mcp:tool"], now=NOW, max_depth=2)
    assert exc.value.reason_code == "INVALID_DELEGATION"


def test_replay_credential_and_invocation():
    auth = _root()
    store = MemoryReplayStore()
    rev = MemoryRevocationStore()
    usage = MemoryUsageStore()
    assert verify(
        auth,
        "deploy",
        "environment:staging",
        {"invocation_id": "call-1"},
        replay_store=store,
        revocation_store=rev,
        usage_store=usage,
        now=NOW,
    ).allowed
    denied = verify(
        auth,
        "deploy",
        "environment:staging",
        {"invocation_id": "call-1"},
        replay_store=store,
        revocation_store=rev,
        usage_store=usage,
        now=NOW,
    )
    assert denied.reason_code == "REPLAY_DETECTED"

    clone = copy.deepcopy(auth.to_dict())
    clone["nonce"] = "00" * 16
    # same id, different nonce, valid signature from a new mint
    twin = mint(
        issuer=auth.issuer,
        subject=auth.subject,
        parent=None,
        capabilities=auth.capabilities,
        resources=auth.resources,
        constraints=auth.constraints,
        issued_at=auth.issued_at,
        expires_at=auth.expires_at,
        delegation_depth=0,
        signing_key=auth.issuer.signing_key(),
        authority_id=auth.id,
        nonce="aa" * 16,
    )
    dup = verify(
        twin,
        "deploy",
        "environment:staging",
        replay_store=store,
        revocation_store=rev,
        usage_store=usage,
        now=NOW,
    )
    assert dup.reason_code == "REPLAY_DETECTED"


def test_revocation_of_mid_chain_invalidates_descendants():
    root = grant(
        "agent:a",
        ["read"],
        ["database:*"],
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
    )
    mid = delegate(root, "agent:b", ["read"], ["database:customers"], now=NOW)
    leaf = delegate(mid, "agent:c", ["read"], ["database:customers"], now=NOW)
    rev = MemoryRevocationStore()
    store_kwargs = dict(
        revocation_store=rev,
        replay_store=MemoryReplayStore(),
        usage_store=MemoryUsageStore(),
        now=NOW,
    )
    assert verify(leaf, "read", "database:customers", **store_kwargs).allowed
    rev.revoke(mid.id)
    denied = verify(leaf, "read", "database:customers", **store_kwargs)
    assert denied.reason_code == "REVOKED"
    assert denied.details["authority_id"] == mid.id


def test_serialization_determinism():
    issuer = Principal.generate("human:alice", seed=bytes(range(32)))
    subject = Principal.generate("agent:deploy", seed=bytes(range(1, 33)))
    a = grant(
        subject,
        ["deploy", "read"],
        ["environment:staging", "environment:dev"],
        {"max_deploys_per_hour": 3, "region": {"op": "eq", "value": "eu"}},
        issuer=issuer,
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
        authority_id="11111111-1111-1111-1111-111111111111",
        nonce="ab" * 16,
    )
    b = grant(
        subject,
        ["read", "deploy"],
        ["environment:dev", "environment:staging"],
        {"region": {"op": "eq", "value": "eu"}, "max_deploys_per_hour": 3},
        issuer=issuer,
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
        authority_id="11111111-1111-1111-1111-111111111111",
        nonce="ab" * 16,
    )
    assert a.canonical_unsigned() == b.canonical_unsigned()
    assert a.signature == b.signature
    assert a.to_json_bytes() == b.to_json_bytes()


def test_capability_not_granted_and_resource_denied():
    auth = _root()
    cap = verify(auth, "write", "environment:staging", now=NOW)
    assert cap.reason_code == "CAPABILITY_NOT_GRANTED"
    res = verify(auth, "deploy", "environment:production", now=NOW)
    assert res.reason_code == "RESOURCE_NOT_ALLOWED"


def test_star_resource_root_only():
    root = grant(
        "agent:wide",
        ["read"],
        ["*"],
        now=NOW,
        expires_at="2026-09-07T12:00:00Z",
    )
    assert verify(root, "read", "anything:here", now=NOW).allowed
    with pytest.raises(DelegationError):
        delegate(root, "agent:child", ["read"], ["*"], now=NOW)
    child = delegate(root, "agent:child", ["read"], ["database:customers"], now=NOW)
    assert verify(child, "read", "database:customers", now=NOW).allowed
