"""Server middleware: verify a Pigeon Pass before a tool runs."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from pigeon.core.authority import Authority
from pigeon.core.result import VerificationResult
from pigeon.verification.verifier import verify


def verify_tool_call(
    authority: Authority | dict[str, Any],
    tool_name: str,
    resource: str,
    arguments: Mapping[str, Any] | None = None,
    **verify_kwargs: Any,
) -> VerificationResult:
    """Verify that `authority` permits this tool invocation."""
    return verify(
        authority,
        tool_name,
        resource,
        dict(arguments or {}),
        **verify_kwargs,
    )


def execute_tool(
    authority: Authority | dict[str, Any],
    tool_name: str,
    resource: str,
    arguments: Mapping[str, Any],
    handler: Callable[..., Any],
    **verify_kwargs: Any,
) -> dict[str, Any]:
    """Run `handler` only if verification succeeds. Structured denial otherwise."""
    result = verify_tool_call(
        authority, tool_name, resource, arguments, **verify_kwargs
    )
    if not result.allowed:
        return {
            "allowed": False,
            "reason_code": result.reason_code,
            "message": result.message,
            "details": result.details,
        }
    return {
        "allowed": True,
        "result": handler(**dict(arguments)),
    }
