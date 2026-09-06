"""Generic principals. Not every principal is an AI agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pigeon.crypto.keys import generate_keypair, private_key_from_b64u, public_key_from_b64u

PRINCIPAL_TYPES = ("human", "agent", "service", "organization")
PrincipalType = Literal["human", "agent", "service", "organization"]

_PREFIX_TO_TYPE = {
    "human": "human",
    "agent": "agent",
    "service": "service",
    "organization": "organization",
    "org": "organization",
}

# Process-local map of public_key -> private_key for keys this process created.
# Applications that supply their own keys may register them. Never serialized.
_KEYRING: dict[str, str] = {}


def register_private_key(public_key: str, private_key: str) -> None:
    private_key_from_b64u(private_key)
    public_key_from_b64u(public_key)
    _KEYRING[public_key] = private_key


def lookup_private_key(public_key: str) -> str | None:
    return _KEYRING.get(public_key)


def infer_principal_type(principal_id: str) -> PrincipalType:
    if ":" in principal_id:
        prefix = principal_id.split(":", 1)[0]
        mapped = _PREFIX_TO_TYPE.get(prefix)
        if mapped is not None:
            return mapped  # type: ignore[return-value]
    return "agent"


@dataclass
class Principal:
    principal_id: str
    principal_type: str
    public_key: str
    _private_key: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.principal_id or not isinstance(self.principal_id, str):
            raise ValueError("principal_id must be a non-empty string")
        if self.principal_type not in PRINCIPAL_TYPES:
            raise ValueError(
                f"principal_type must be one of {PRINCIPAL_TYPES}"
            )
        public_key_from_b64u(self.public_key)
        if self._private_key is not None:
            register_private_key(self.public_key, self._private_key)

    @classmethod
    def generate(
        cls,
        principal_id: str,
        principal_type: str | None = None,
        *,
        seed: bytes | None = None,
    ) -> Principal:
        if principal_type is None:
            principal_type = infer_principal_type(principal_id)
        if seed is not None:
            from pigeon.crypto.keys import keypair_from_seed

            public, private = keypair_from_seed(seed)
        else:
            public, private = generate_keypair()
        return cls(
            principal_id=principal_id,
            principal_type=principal_type,
            public_key=public,
            _private_key=private,
        )

    @classmethod
    def from_id(cls, principal_id: str) -> Principal:
        return cls.generate(principal_id)

    def signing_key(self) -> str:
        key = self._private_key or lookup_private_key(self.public_key)
        if key is None:
            raise ValueError(
                f"no private key available for principal {self.principal_id}"
            )
        return key

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "public_key": self.public_key,
        }

    @classmethod
    def from_dict(cls, data: Any) -> Principal:
        if not isinstance(data, dict):
            raise ValueError("principal must be an object")
        extra = set(data) - {"principal_id", "principal_type", "public_key"}
        if extra:
            raise ValueError(f"principal has unknown fields: {sorted(extra)}")
        try:
            return cls(
                principal_id=data["principal_id"],
                principal_type=data["principal_type"],
                public_key=data["public_key"],
                _private_key=lookup_private_key(data["public_key"]),
            )
        except KeyError as exc:
            raise ValueError(f"principal missing field {exc}") from exc

    def identity_matches(self, other: Principal) -> bool:
        return (
            self.principal_id == other.principal_id
            and self.principal_type == other.principal_type
            and self.public_key == other.public_key
        )
