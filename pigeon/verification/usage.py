"""In-process usage counters for rate and count constraints."""

from __future__ import annotations

from collections import defaultdict


class MemoryUsageStore:
    def __init__(self) -> None:
        self._events: dict[tuple[str, str], list[tuple[int, int]]] = defaultdict(list)
        self._totals: dict[tuple[str, str], int] = defaultdict(int)

    def add(self, authority_id: str, dimension: str, amount: int, now_unix: int) -> None:
        key = (authority_id, dimension)
        self._events[key].append((now_unix, amount))
        self._totals[key] += amount

    def total(self, authority_id: str, dimension: str) -> int:
        return self._totals[(authority_id, dimension)]

    def window_total(
        self, authority_id: str, dimension: str, window_seconds: int, now_unix: int
    ) -> int:
        key = (authority_id, dimension)
        start = now_unix - window_seconds
        total = 0
        kept: list[tuple[int, int]] = []
        for ts, amount in self._events[key]:
            if ts > start:
                kept.append((ts, amount))
                total += amount
        self._events[key] = kept
        return total
