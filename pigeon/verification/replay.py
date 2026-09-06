"""ReplayStore: credential uniqueness and runtime invocation replay."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ReplayStore(Protocol):
    def remember_credential(self, authority_id: str, nonce: str) -> bool:
        """Record (id, nonce). Return False if id exists with a different nonce."""

    def seen_invocation(self, authority_id: str, invocation_id: str) -> bool:
        """Return True if this invocation_id was already recorded for the authority."""

    def remember_invocation(self, authority_id: str, invocation_id: str) -> None:
        """Record a runtime invocation id."""


class MemoryReplayStore:
    def __init__(self) -> None:
        self._credentials: dict[str, str] = {}
        self._invocations: set[tuple[str, str]] = set()

    def remember_credential(self, authority_id: str, nonce: str) -> bool:
        existing = self._credentials.get(authority_id)
        if existing is None:
            self._credentials[authority_id] = nonce
            return True
        return existing == nonce

    def seen_invocation(self, authority_id: str, invocation_id: str) -> bool:
        return (authority_id, invocation_id) in self._invocations

    def remember_invocation(self, authority_id: str, invocation_id: str) -> None:
        self._invocations.add((authority_id, invocation_id))
