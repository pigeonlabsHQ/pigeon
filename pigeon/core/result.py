"""Structured authorization result. Never a bare boolean."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

REASON_CODES = (
    "INVALID_SIGNATURE",
    "EXPIRED",
    "INVALID_ISSUER",
    "INVALID_PARENT",
    "CAPABILITY_NOT_GRANTED",
    "RESOURCE_NOT_ALLOWED",
    "CONSTRAINT_VIOLATION",
    "PRIVILEGE_ESCALATION",
    "INVALID_DELEGATION",
    "REPLAY_DETECTED",
    "RATE_LIMIT_EXCEEDED",
    "REVOKED",
    "MALFORMED_AUTHORITY",
)


@dataclass(frozen=True)
class VerificationResult:
    allowed: bool
    reason_code: str | None
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    steps: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def __bool__(self) -> bool:
        return self.allowed


def allow(*, message: str = "allowed", details: dict[str, Any] | None = None,
          steps: tuple[dict[str, Any], ...] = ()) -> VerificationResult:
    return VerificationResult(
        allowed=True,
        reason_code=None,
        message=message,
        details=details or {},
        steps=steps,
    )


def deny(
    reason_code: str,
    message: str,
    *,
    details: dict[str, Any] | None = None,
    steps: tuple[dict[str, Any], ...] = (),
) -> VerificationResult:
    if reason_code not in REASON_CODES:
        raise ValueError(f"unknown reason code {reason_code}")
    return VerificationResult(
        allowed=False,
        reason_code=reason_code,
        message=message,
        details=details or {},
        steps=steps,
    )


class DelegationError(Exception):
    """Raised when grant or delegate fail closed."""

    def __init__(
        self,
        reason_code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message
        self.details = details or {}
