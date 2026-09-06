"""Client helper: mint an attenuated Pass for a single MCP tool call."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pigeon.core.authority import Authority
from pigeon.core.delegation import delegate
from pigeon.core.principal import Principal


def pass_for_tool(
    authority: Authority,
    tool_name: str,
    resource: str,
    *,
    subject: str | Principal | None = None,
    capabilities: Sequence[str] | None = None,
    constraints: Mapping[str, Any] | None = None,
    **delegate_kwargs: Any,
) -> Authority:
    """Delegate a Pass narrowed to one tool name and one resource."""
    caps = list(capabilities) if capabilities is not None else [tool_name]
    subj = subject if subject is not None else f"agent:mcp:{tool_name}"
    return delegate(
        authority,
        subj,
        caps,
        [resource],
        constraints,
        **delegate_kwargs,
    )
