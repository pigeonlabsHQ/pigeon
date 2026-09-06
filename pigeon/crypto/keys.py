"""Key encoding helpers. Pigeon does not store or rotate keys."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(data: str) -> bytes:
    if not isinstance(data, str) or not data:
        raise ValueError("expected non-empty base64url string")
    pad = "=" * ((4 - len(data) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(data + pad)
    except Exception as exc:
        raise ValueError("invalid base64url") from exc


def generate_keypair() -> tuple[str, str]:
    """Return `(public_key, private_key)` as unpadded base64url strings."""
    private = Ed25519PrivateKey.generate()
    return public_key_to_b64u(private.public_key()), private_key_to_b64u(private)


def public_key_to_b64u(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b64u_encode(raw)


def private_key_to_b64u(private: Ed25519PrivateKey) -> str:
    return b64u_encode(private.private_bytes_raw())


def private_key_from_b64u(data: str) -> Ed25519PrivateKey:
    raw = b64u_decode(data)
    if len(raw) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_from_b64u(data: str) -> Ed25519PublicKey:
    raw = b64u_decode(data)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def keypair_from_seed(seed: bytes) -> tuple[str, str]:
    """Deterministic keypair for fixtures. `seed` must be 32 bytes."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return public_key_to_b64u(private.public_key()), private_key_to_b64u(private)
