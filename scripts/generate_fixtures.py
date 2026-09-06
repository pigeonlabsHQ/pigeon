"""Deterministic protocol fixtures. Run: python scripts/generate_fixtures.py"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pigeon import Principal, delegate, grant  # noqa: E402
from pigeon.core.authority import Authority  # noqa: E402

NOW = "2026-01-01T00:00:00Z"
EXP = "2026-01-02T00:00:00Z"
ISSUER = Principal.generate("human:alice", "human", seed=bytes([1]) * 32)
SUBJECT = Principal.generate("agent:deploy", "agent", seed=bytes([2]) * 32)
RUNNER = Principal.generate("agent:runner", "agent", seed=bytes([3]) * 32)
READER = Principal.generate("agent:reader", "agent", seed=bytes([4]) * 32)

ROOT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
CHILD_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
ROOT_NONCE = "11" * 16
CHILD_NONCE = "22" * 16

FIXTURES = ROOT / "fixtures"


def _dump(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _keys() -> dict:
    return {
        ISSUER.principal_id: ISSUER.signing_key(),
        SUBJECT.principal_id: SUBJECT.signing_key(),
        RUNNER.principal_id: RUNNER.signing_key(),
        READER.principal_id: READER.signing_key(),
    }


def _root(**kwargs):
    defaults = dict(
        subject=SUBJECT,
        capabilities=["deploy"],
        resources=["environment:staging"],
        issuer=ISSUER,
        now=NOW,
        expires_at=EXP,
        authority_id=ROOT_ID,
        nonce=ROOT_NONCE,
    )
    defaults.update(kwargs)
    return grant(**defaults)


def _verify_case(name: str, folder: str, authority: Authority, expected: dict, **input_extra):
    payload = {
        "id": name,
        "comment": input_extra.pop("comment", name),
        "keys": _keys(),
        "pass": authority.to_pass_document(),
        "action": input_extra.pop("action", "deploy"),
        "resource": input_extra.pop("resource", "environment:staging"),
        "context": input_extra.pop("context", {}),
        "now": NOW,
        "expected": expected,
    }
    payload.update(input_extra)
    _dump(FIXTURES / folder / f"{name}.json", payload)


def main() -> None:
    for sub in ("valid", "invalid", "delegation", "attenuation", "tampering"):
        (FIXTURES / sub).mkdir(parents=True, exist_ok=True)
        for old in (FIXTURES / sub).glob("*.json"):
            old.unlink()

    root = _root()
    _verify_case(
        "valid-root-allow",
        "valid",
        root,
        {"allowed": True, "reason_code": None},
        comment="Root grant permits deploy to staging",
    )
    wide = _root(
        resources=["environment:*"],
        constraints={"max_deploys_per_hour": 3},
    )
    child = delegate(
        wide,
        RUNNER,
        ["deploy"],
        ["environment:staging"],
        {"max_deploys_per_hour": 1},
        now=NOW,
        authority_id=CHILD_ID,
        nonce=CHILD_NONCE,
    )
    _verify_case(
        "valid-delegated-allow",
        "valid",
        child,
        {"allowed": True, "reason_code": None},
        comment="Narrowed child may deploy to staging",
    )
    _verify_case(
        "valid-wildcard-match",
        "valid",
        wide,
        {"allowed": True, "reason_code": None},
        resource="environment:staging",
        comment="Trailing wildcard matches a suffix in the same namespace",
    )

    _verify_case(
        "invalid-expired",
        "invalid",
        root,
        {"allowed": False, "reason_code": "EXPIRED"},
        now="2026-01-03T00:00:00Z",
        comment="Expired pass is denied",
    )
    _verify_case(
        "invalid-capability",
        "invalid",
        root,
        {"allowed": False, "reason_code": "CAPABILITY_NOT_GRANTED"},
        action="write",
        comment="Action not in capabilities",
    )
    _verify_case(
        "invalid-resource",
        "invalid",
        root,
        {"allowed": False, "reason_code": "RESOURCE_NOT_ALLOWED"},
        resource="environment:production",
        comment="Production is outside staging",
    )
    shop = grant(
        READER,
        ["purchase"],
        ["merchant:books"],
        {"amount": 50},
        issuer=ISSUER,
        now=NOW,
        expires_at=EXP,
        authority_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        nonce="33" * 16,
    )
    _verify_case(
        "invalid-constraint",
        "invalid",
        shop,
        {"allowed": False, "reason_code": "CONSTRAINT_VIOLATION"},
        action="purchase",
        resource="merchant:books",
        context={"amount": 75},
        comment="75 exceeds max amount 50",
    )

    parent_for_del = grant(
        SUBJECT,
        ["read"],
        ["database:customers"],
        issuer=ISSUER,
        now=NOW,
        expires_at=EXP,
        authority_id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        nonce="44" * 16,
    )
    _dump(
        FIXTURES / "delegation" / "delegation-valid-narrow.json",
        {
            "id": "delegation-valid-narrow",
            "comment": "Child requests a subset of parent capabilities and resources",
            "keys": _keys(),
            "parent": parent_for_del.to_pass_document(),
            "request": {
                "subject": RUNNER.to_dict(),
                "capabilities": ["read"],
                "resources": ["database:customers"],
                "constraints": {},
            },
            "expected": {"success": True, "reason_code": None},
        },
    )
    _dump(
        FIXTURES / "delegation" / "delegation-capability-expansion.json",
        {
            "id": "delegation-capability-expansion",
            "comment": "Child requests write which the parent does not have",
            "keys": _keys(),
            "parent": parent_for_del.to_pass_document(),
            "request": {
                "subject": RUNNER.to_dict(),
                "capabilities": ["read", "write"],
                "resources": ["database:customers"],
                "constraints": {},
            },
            "expected": {"success": False, "reason_code": "PRIVILEGE_ESCALATION"},
        },
    )
    staging = _root()
    _dump(
        FIXTURES / "delegation" / "delegation-resource-expansion.json",
        {
            "id": "delegation-resource-expansion",
            "comment": "Child widens staging to a wildcard",
            "keys": _keys(),
            "parent": staging.to_pass_document(),
            "request": {
                "subject": RUNNER.to_dict(),
                "capabilities": ["deploy"],
                "resources": ["environment:*"],
                "constraints": {},
            },
            "expected": {"success": False, "reason_code": "PRIVILEGE_ESCALATION"},
        },
    )

    capped = grant(
        SUBJECT,
        ["purchase"],
        ["merchant:*"],
        {"amount": 100},
        issuer=ISSUER,
        now=NOW,
        expires_at=EXP,
        authority_id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        nonce="55" * 16,
    )
    _dump(
        FIXTURES / "attenuation" / "attenuation-max-lowered.json",
        {
            "id": "attenuation-max-lowered",
            "comment": "Lowering a numeric upper bound is valid",
            "keys": _keys(),
            "parent": capped.to_pass_document(),
            "request": {
                "subject": RUNNER.to_dict(),
                "capabilities": ["purchase"],
                "resources": ["merchant:books"],
                "constraints": {"amount": {"op": "max", "value": 50}},
            },
            "expected": {"success": True, "reason_code": None},
        },
    )
    _dump(
        FIXTURES / "attenuation" / "attenuation-max-raised.json",
        {
            "id": "attenuation-max-raised",
            "comment": "Raising a numeric upper bound is rejected",
            "keys": _keys(),
            "parent": capped.to_pass_document(),
            "request": {
                "subject": RUNNER.to_dict(),
                "capabilities": ["purchase"],
                "resources": ["merchant:books"],
                "constraints": {"amount": {"op": "max", "value": 200}},
            },
            "expected": {"success": False, "reason_code": "PRIVILEGE_ESCALATION"},
        },
    )
    _dump(
        FIXTURES / "attenuation" / "attenuation-constraint-removed.json",
        {
            "id": "attenuation-constraint-removed",
            "comment": "Removing a parent constraint is rejected",
            "keys": _keys(),
            "parent": capped.to_pass_document(),
            "request": {
                "subject": RUNNER.to_dict(),
                "capabilities": ["purchase"],
                "resources": ["merchant:books"],
                "constraints": {},
            },
            "expected": {"success": False, "reason_code": "PRIVILEGE_ESCALATION"},
        },
    )
    _dump(
        FIXTURES / "attenuation" / "attenuation-constraint-added.json",
        {
            "id": "attenuation-constraint-added",
            "comment": "Adding a constraint the parent does not have is valid",
            "keys": _keys(),
            "parent": capped.to_pass_document(),
            "request": {
                "subject": RUNNER.to_dict(),
                "capabilities": ["purchase"],
                "resources": ["merchant:books"],
                "constraints": {
                    "amount": {"op": "max", "value": 100},
                    "currency": {"op": "eq", "value": "EUR"},
                },
            },
            "expected": {"success": True, "reason_code": None},
        },
    )

    signed = root.to_dict()
    fields = {
        "id": "00000000-0000-4000-8000-000000000000",
        "issuer": RUNNER.to_dict(),
        "subject": RUNNER.to_dict(),
        "capabilities": ["deploy", "write"],
        "resources": ["environment:production"],
        "constraints": {"region": {"op": "eq", "value": "us"}},
        "issued_at": "2025-01-01T00:00:00Z",
        "expires_at": "2026-06-01T00:00:00Z",
        "nonce": "ff" * 16,
        "delegation_depth": 4,
        "signature": "A" * 86,
    }
    for field, value in fields.items():
        tampered = dict(signed)
        tampered[field] = value
        _dump(
            FIXTURES / "tampering" / f"tamper-{field}.json",
            {
                "id": f"tamper-{field}",
                "comment": f"Tampering with signed field {field}",
                "keys": _keys(),
                "pass": {"authorities": [tampered]},
                "action": "deploy",
                "resource": "environment:staging",
                "context": {},
                "now": NOW,
                "expected": {
                    "allowed": False,
                    "reason_code": "INVALID_SIGNATURE"
                    if field != "signature"
                    else "INVALID_SIGNATURE",
                },
            },
        )


if __name__ == "__main__":
    main()
