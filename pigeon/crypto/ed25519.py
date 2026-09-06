"""Ed25519 sign and verify via the cryptography library."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature

from pigeon.crypto.keys import (
    b64u_decode,
    b64u_encode,
    private_key_from_b64u,
    public_key_from_b64u,
)


def sign(message: bytes, private_key: str) -> str:
    """Sign `message` and return an unpadded base64url signature."""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    key = private_key_from_b64u(private_key)
    return b64u_encode(key.sign(bytes(message)))


def verify_signature(message: bytes, signature: str, public_key: str) -> bool:
    """Return True iff `signature` is a valid Ed25519 signature over `message`."""
    if not isinstance(message, (bytes, bytearray)):
        return False
    try:
        key = public_key_from_b64u(public_key)
        sig = b64u_decode(signature)
        if len(sig) != 64:
            return False
        key.verify(sig, bytes(message))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
