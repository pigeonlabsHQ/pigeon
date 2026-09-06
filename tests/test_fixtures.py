"""Run committed conformance fixtures and assert regeneration is byte-identical."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pigeon import Authority, DelegationError, Principal, delegate, verify
from pigeon.core.principal import register_private_key
from pigeon.verification.replay import MemoryReplayStore
from pigeon.verification.revocation import MemoryRevocationStore
from pigeon.verification.usage import MemoryUsageStore

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _register_keys(payload: dict) -> None:
    for _pid, key in payload.get("keys", {}).items():
        # Recover public key from the pass where possible; register by scanning principals.
        pass
    def _walk(obj):
        if isinstance(obj, dict):
            if "public_key" in obj and "principal_id" in obj:
                pid = obj["principal_id"]
                if pid in payload.get("keys", {}):
                    register_private_key(obj["public_key"], payload["keys"][pid])
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v)
    _walk(payload)


def _stores():
    return dict(
        replay_store=MemoryReplayStore(),
        revocation_store=MemoryRevocationStore(),
        usage_store=MemoryUsageStore(),
    )


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("valid/*.json")))
def test_valid_fixtures(path: Path):
    payload = _load(path)
    _register_keys(payload)
    auth = Authority.from_pass_document(payload["pass"])
    result = verify(
        auth,
        payload["action"],
        payload["resource"],
        payload.get("context") or {},
        now=payload.get("now"),
        **_stores(),
    )
    assert result.allowed is payload["expected"]["allowed"]
    assert result.reason_code == payload["expected"]["reason_code"]


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("invalid/*.json")))
def test_invalid_fixtures(path: Path):
    payload = _load(path)
    _register_keys(payload)
    auth = Authority.from_pass_document(payload["pass"])
    result = verify(
        auth,
        payload["action"],
        payload["resource"],
        payload.get("context") or {},
        now=payload.get("now"),
        **_stores(),
    )
    assert result.allowed is False
    assert result.reason_code == payload["expected"]["reason_code"]


@pytest.mark.parametrize(
    "path",
    sorted(FIXTURES.glob("delegation/*.json")) + sorted(FIXTURES.glob("attenuation/*.json")),
)
def test_delegation_fixtures(path: Path):
    payload = _load(path)
    _register_keys(payload)
    parent = Authority.from_pass_document(payload["parent"])
    req = payload["request"]
    subject = Principal.from_dict(req["subject"])
    expected = payload["expected"]
    try:
        child = delegate(
            parent,
            subject,
            req["capabilities"],
            req["resources"],
            req.get("constraints") or {},
            now="2026-01-01T00:00:00Z",
        )
    except DelegationError as exc:
        assert expected["success"] is False
        assert exc.reason_code == expected["reason_code"]
        return
    assert expected["success"] is True
    assert child.parent == parent.id


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("tampering/*.json")))
def test_tampering_fixtures(path: Path):
    payload = _load(path)
    try:
        auth = Authority.from_pass_document(payload["pass"])
    except Exception:
        return
    result = verify(
        auth,
        payload["action"],
        payload["resource"],
        payload.get("context") or {},
        now=payload.get("now"),
        **_stores(),
    )
    assert result.allowed is False
    assert result.reason_code in {
        "INVALID_SIGNATURE",
        "INVALID_PARENT",
        "INVALID_DELEGATION",
        "MALFORMED_AUTHORITY",
        "EXPIRED",
        "PRIVILEGE_ESCALATION",
    }


def test_fixtures_are_byte_deterministic():
    script = ROOT / "scripts" / "generate_fixtures.py"
    before = {
        p.relative_to(FIXTURES): p.read_bytes()
        for p in sorted(FIXTURES.rglob("*.json"))
    }
    subprocess.run([sys.executable, str(script)], check=True, cwd=str(ROOT))
    after = {
        p.relative_to(FIXTURES): p.read_bytes()
        for p in sorted(FIXTURES.rglob("*.json"))
    }
    assert before == after
