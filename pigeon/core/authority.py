"""Authority object: the 13 protocol fields plus an in-memory ancestor chain."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from pigeon.core.capability import normalize_capabilities
from pigeon.core.constraints import normalize_constraints
from pigeon.core.principal import Principal
from pigeon.core.resource import normalize_resources
from pigeon.crypto.canonicalization import CanonicalError, canonicalize
from pigeon.crypto.ed25519 import sign, verify_signature

PROTOCOL_VERSION = 1
AUTHORITY_FIELDS = (
    "id",
    "version",
    "issuer",
    "subject",
    "parent",
    "capabilities",
    "resources",
    "constraints",
    "issued_at",
    "expires_at",
    "nonce",
    "delegation_depth",
    "signature",
)
SIGNED_FIELDS = tuple(f for f in AUTHORITY_FIELDS if f != "signature")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def format_time(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware UTC")
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime(TIME_FORMAT)


def parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    try:
        dt = datetime.strptime(value, TIME_FORMAT)
    except ValueError as exc:
        raise ValueError(
            "timestamp must be UTC RFC 3339 with second precision and a Z suffix"
        ) from exc
    return dt.replace(tzinfo=timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


def new_nonce() -> str:
    return secrets.token_hex(16)


@dataclass
class Authority:
    id: str
    version: int
    issuer: Principal
    subject: Principal
    parent: str | None
    capabilities: list[str]
    resources: list[str]
    constraints: dict[str, Any]
    issued_at: str
    expires_at: str
    nonce: str
    delegation_depth: int
    signature: str
    _ancestors: tuple[Authority, ...] = field(default=(), repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "issuer": self.issuer.to_dict(),
            "subject": self.subject.to_dict(),
            "parent": self.parent,
            "capabilities": list(self.capabilities),
            "resources": list(self.resources),
            "constraints": dict(self.constraints),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "delegation_depth": self.delegation_depth,
            "signature": self.signature,
        }

    def unsigned_dict(self) -> dict[str, Any]:
        data = self.to_dict()
        data.pop("signature", None)
        return data

    def canonical_unsigned(self) -> bytes:
        return canonicalize(self.unsigned_dict())

    def to_pass_document(self) -> dict[str, Any]:
        return {"authorities": [self.to_dict(), *[a.to_dict() for a in self._ancestors]]}

    def to_json_bytes(self) -> bytes:
        return canonicalize(self.to_pass_document())

    def chain(self) -> list[Authority]:
        """Leaf first, root last."""
        return [self, *self._ancestors]

    def root(self) -> Authority:
        chain = self.chain()
        return chain[-1]

    def verify_own_signature(self) -> bool:
        try:
            payload = canonicalize(self.unsigned_dict())
        except CanonicalError:
            return False
        return verify_signature(payload, self.signature, self.issuer.public_key)

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        *,
        ancestors: tuple[Authority, ...] = (),
    ) -> Authority:
        if not isinstance(data, dict):
            raise ValueError("authority must be an object")
        extra = set(data) - set(AUTHORITY_FIELDS)
        if extra:
            raise ValueError(f"authority has unknown fields: {sorted(extra)}")
        missing = [f for f in AUTHORITY_FIELDS if f not in data]
        if missing:
            raise ValueError(f"authority missing fields: {missing}")
        parent = data["parent"]
        if parent is not None and (not isinstance(parent, str) or parent == ""):
            raise ValueError("parent must be an authority id or null")
        if data["version"] != PROTOCOL_VERSION:
            raise ValueError("unsupported authority version")
        if not isinstance(data["id"], str) or not data["id"]:
            raise ValueError("id must be a non-empty string")
        if not isinstance(data["nonce"], str) or not data["nonce"]:
            raise ValueError("nonce must be a non-empty string")
        if not isinstance(data["signature"], str) or not data["signature"]:
            raise ValueError("signature must be a non-empty string")
        depth = data["delegation_depth"]
        if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
            raise ValueError("delegation_depth must be a non-negative integer")
        issued_at = parse_time(data["issued_at"])
        expires_at = parse_time(data["expires_at"])
        if expires_at <= issued_at:
            raise ValueError("expires_at must be after issued_at")
        is_root = parent is None
        capabilities = normalize_capabilities(data["capabilities"])
        resources = normalize_resources(data["resources"], is_root=is_root)
        constraints = normalize_constraints(data["constraints"])
        auth = cls(
            id=data["id"],
            version=data["version"],
            issuer=Principal.from_dict(data["issuer"]),
            subject=Principal.from_dict(data["subject"]),
            parent=parent,
            capabilities=capabilities,
            resources=resources,
            constraints=constraints,
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            nonce=data["nonce"],
            delegation_depth=depth,
            signature=data["signature"],
            _ancestors=ancestors,
        )
        return auth

    @classmethod
    def from_pass_document(cls, document: dict[str, Any]) -> Authority:
        if not isinstance(document, dict) or set(document.keys()) != {"authorities"}:
            raise ValueError("pass document must be an object with key authorities")
        items = document["authorities"]
        if not isinstance(items, list) or not items:
            raise ValueError("authorities must be a non-empty array")
        parsed = [cls.from_dict(item) for item in items]
        leaf = parsed[0]
        ancestors = tuple(parsed[1:])
        return leaf.with_ancestors(ancestors)

    def with_ancestors(self, ancestors: tuple[Authority, ...]) -> Authority:
        return Authority(
            id=self.id,
            version=self.version,
            issuer=self.issuer,
            subject=self.subject,
            parent=self.parent,
            capabilities=self.capabilities,
            resources=self.resources,
            constraints=self.constraints,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            nonce=self.nonce,
            delegation_depth=self.delegation_depth,
            signature=self.signature,
            _ancestors=ancestors,
        )


def mint(
    *,
    issuer: Principal,
    subject: Principal,
    parent: str | None,
    capabilities: list[str],
    resources: list[str],
    constraints: dict[str, Any],
    issued_at: str,
    expires_at: str,
    delegation_depth: int,
    signing_key: str,
    ancestors: tuple[Authority, ...] = (),
    authority_id: str | None = None,
    nonce: str | None = None,
) -> Authority:
    unsigned = {
        "id": authority_id or new_id(),
        "version": PROTOCOL_VERSION,
        "issuer": issuer.to_dict(),
        "subject": subject.to_dict(),
        "parent": parent,
        "capabilities": capabilities,
        "resources": resources,
        "constraints": constraints,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce or new_nonce(),
        "delegation_depth": delegation_depth,
    }
    payload = canonicalize(unsigned)
    signature = sign(payload, signing_key)
    return Authority.from_dict({**unsigned, "signature": signature}, ancestors=ancestors)


def default_expiry(issued_at: datetime, ttl_seconds: int) -> datetime:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    return issued_at + timedelta(seconds=ttl_seconds)
