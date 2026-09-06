"""RevocationStore interface. Revoking an authority invalidates descendants."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class RevocationStore(Protocol):
    def revoke(self, authority_id: str) -> None:
        """Mark an authority id as revoked."""

    def is_revoked(self, authority_id: str) -> bool:
        """Return True if this authority id has been revoked."""


class MemoryRevocationStore:
    def __init__(self) -> None:
        self._revoked: set[str] = set()

    def revoke(self, authority_id: str) -> None:
        self._revoked.add(authority_id)

    def is_revoked(self, authority_id: str) -> bool:
        return authority_id in self._revoked
