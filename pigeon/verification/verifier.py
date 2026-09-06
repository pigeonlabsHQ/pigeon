"""Verify a Pigeon Pass against an action, resource, and context."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pigeon.core.authority import Authority, parse_time, utcnow
from pigeon.core.capability import normalize_capabilities
from pigeon.core.constraints import (
    STATEFUL_OPS,
    evaluate_stateless,
    increment_for,
)
from pigeon.core.resource import any_resource_matches
from pigeon.core.result import VerificationResult, allow, deny
from pigeon.verification.chain import assemble_steps, structural_chain_error
from pigeon.verification.replay import MemoryReplayStore, ReplayStore
from pigeon.verification.revocation import MemoryRevocationStore, RevocationStore
from pigeon.verification.usage import MemoryUsageStore

DEFAULT_MAX_DEPTH = 8

_default_replay = MemoryReplayStore()
_default_revocation = MemoryRevocationStore()
_default_usage = MemoryUsageStore()


def default_replay_store() -> MemoryReplayStore:
    return _default_replay


def default_revocation_store() -> MemoryRevocationStore:
    return _default_revocation


def default_usage_store() -> MemoryUsageStore:
    return _default_usage


def reset_default_stores() -> None:
    global _default_replay, _default_revocation, _default_usage
    _default_replay = MemoryReplayStore()
    _default_revocation = MemoryRevocationStore()
    _default_usage = MemoryUsageStore()


def verify(
    authority: Authority | dict[str, Any],
    action: str,
    resource: str,
    context: Mapping[str, Any] | None = None,
    *,
    replay_store: ReplayStore | None = None,
    revocation_store: RevocationStore | None = None,
    usage_store: MemoryUsageStore | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    now: str | None = None,
) -> VerificationResult:
    ctx = dict(context or {})
    replay_store = replay_store or _default_replay
    revocation_store = revocation_store or _default_revocation
    usage_store = usage_store or _default_usage
    try:
        auth = _coerce_authority(authority)
        clock = parse_time(now) if now is not None else (
            parse_time(ctx["now"]) if "now" in ctx else utcnow()
        )
    except Exception as exc:
        return deny("MALFORMED_AUTHORITY", str(exc))
    if not isinstance(action, str) or not action:
        return deny(
            "CAPABILITY_NOT_GRANTED",
            "action must be a non-empty string",
            details={"requested": action},
        )
    if not isinstance(resource, str) or not resource:
        return deny(
            "RESOURCE_NOT_ALLOWED",
            "resource must be a non-empty string",
            details={"requested": resource},
        )

    chain_err = structural_chain_error(
        auth, now=clock, max_depth=max_depth, revocation_store=revocation_store
    )
    if chain_err is not None:
        return chain_err

    steps = tuple(assemble_steps(auth))

    if not replay_store.remember_credential(auth.id, auth.nonce):
        return deny(
            "REPLAY_DETECTED",
            "authority id was reused with a different nonce",
            details={"authority_id": auth.id},
            steps=steps,
        )
    invocation_id = ctx.get("invocation_id")
    if invocation_id is not None:
        if not isinstance(invocation_id, str) or not invocation_id:
            return deny(
                "MALFORMED_AUTHORITY",
                "invocation_id must be a non-empty string",
            )
        if replay_store.seen_invocation(auth.id, invocation_id):
            return deny(
                "REPLAY_DETECTED",
                "duplicate invocation_id",
                details={"authority_id": auth.id, "invocation_id": invocation_id},
                steps=steps,
            )

    try:
        normalize_capabilities([action])
    except ValueError:
        return deny(
            "CAPABILITY_NOT_GRANTED",
            "action is not a valid capability string",
            details={"requested": action},
        )
    if action not in auth.capabilities:
        return deny(
            "CAPABILITY_NOT_GRANTED",
            "action is not granted by this authority",
            details={
                "requested": action,
                "allowed": list(auth.capabilities),
            },
            steps=steps,
        )
    if not any_resource_matches(auth.resources, resource):
        return deny(
            "RESOURCE_NOT_ALLOWED",
            "resource is not granted by this authority",
            details={
                "requested": resource,
                "allowed": list(auth.resources),
            },
            steps=steps,
        )

    reason, message, details = evaluate_stateless(auth.constraints, ctx)
    if reason:
        return deny(reason, message, details=details, steps=steps)

    now_unix = int(clock.timestamp())
    stateful_err = _check_stateful(auth, ctx, usage_store, now_unix)
    if stateful_err is not None:
        return deny(
            stateful_err[0],
            stateful_err[1],
            details=stateful_err[2],
            steps=steps,
        )

    _record_stateful(auth, ctx, usage_store, now_unix)
    if invocation_id is not None:
        replay_store.remember_invocation(auth.id, invocation_id)
    return allow(details={"action": action, "resource": resource}, steps=steps)


def _coerce_authority(value: Authority | dict[str, Any]) -> Authority:
    if isinstance(value, Authority):
        if value.parent is not None and not value._ancestors:
            raise ValueError("delegated authority is missing its parent chain")
        return value
    if isinstance(value, dict) and "authorities" in value:
        return Authority.from_pass_document(value)
    if isinstance(value, dict):
        return Authority.from_dict(value)
    raise ValueError("authority must be an Authority or pass document")


def _check_stateful(
    auth: Authority,
    ctx: Mapping[str, Any],
    usage_store: MemoryUsageStore,
    now_unix: int,
) -> tuple[str, str, dict[str, Any]] | None:
    for link in auth.chain():
        for dim, expr in link.constraints.items():
            if expr["op"] not in STATEFUL_OPS:
                continue
            try:
                amount = increment_for(expr, dim, ctx)
            except ValueError:
                return (
                    "CONSTRAINT_VIOLATION",
                    f"constraint {dim} requires a positive integer increment",
                    {"dimension": dim, "requested": ctx.get(dim)},
                )
            if expr["op"] == "rate":
                used = usage_store.window_total(
                    link.id, dim, expr["window_seconds"], now_unix
                )
                if used + amount > expr["max"]:
                    return (
                        "RATE_LIMIT_EXCEEDED",
                        f"rate constraint {dim} exceeded",
                        {
                            "dimension": dim,
                            "requested": used + amount,
                            "allowed": expr["max"],
                            "window_seconds": expr["window_seconds"],
                            "authority_id": link.id,
                        },
                    )
            elif expr["op"] == "count":
                used = usage_store.total(link.id, dim)
                if used + amount > expr["max"]:
                    return (
                        "CONSTRAINT_VIOLATION",
                        f"count constraint {dim} exceeded",
                        {
                            "dimension": dim,
                            "requested": used + amount,
                            "allowed": expr["max"],
                            "authority_id": link.id,
                        },
                    )
    return None


def _record_stateful(
    auth: Authority,
    ctx: Mapping[str, Any],
    usage_store: MemoryUsageStore,
    now_unix: int,
) -> None:
    for link in auth.chain():
        for dim, expr in link.constraints.items():
            if expr["op"] not in STATEFUL_OPS:
                continue
            amount = increment_for(expr, dim, ctx)
            usage_store.add(link.id, dim, amount, now_unix)
