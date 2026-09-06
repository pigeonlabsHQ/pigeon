# Pigeon v0.1 — working architecture

Working document for the reference implementation. The protocol contract is `SPEC.md`. This file records decisions, ambiguities, and the conservative resolution of each.

## Goal

A language-independent authority protocol with a small Python reference implementation. Identity says who an agent is. A Pigeon Pass says what it may do. A child Pass can never contain more effective authority than its parent.

## Layout

```
pigeon/core/           protocol types (no domain meaning)
pigeon/crypto/         Ed25519 + canonical JSON
pigeon/verification/   chain, attenuation, replay, revocation, usage
pigeon/integrations/mcp/  enforcement point, not protocol
examples/              six scripts, payments last of the four domain ones
fixtures/              language-independent conformance cases
tests/
```

Nothing in `pigeon/core/` knows about money, databases, repos, or deploys. Those strings appear only in examples, fixtures, and tests.

## Public API

Exactly:

```python
from pigeon import Principal, Authority, grant, delegate, verify
```

Necessary companions, not protocol:

- `DelegationError` — `grant` / `delegate` fail closed by raising
- `ReplayStore` / `MemoryReplayStore`
- `RevocationStore` / `MemoryRevocationStore`

Verification is pluggable via optional store arguments on `verify()`. Revocation is an interface with an in-memory implementation. Nothing is built behind those seams.

## Protocol vs SDK sugar

Signed bytes always use the explicit constraint object in `SPEC.md`.

The Python SDK accepts a number of shorthand constraint values (for example `{"max_deploys_per_hour": 3}`) and expands them before signing. Other implementations need only understand the explicit form. They may offer their own sugar. Sugar is not part of the signed protocol.

## Pass document vs Authority

An Authority has exactly the 13 fields in the spec. Chain data is not a 14th field.

A Pass document (the unit you transmit) is:

```json
{"authorities": [<leaf>, <parent>, ..., <root>]}
```

Each element is a signed Authority. The leaf is first. The root is last and has `"parent": null`. Python `Authority` objects hold ancestors in memory so `grant` / `delegate` / `verify` work without a network directory.

## Principals inside issuer and subject

Offline verification requires public keys. `issuer` and `subject` are Principal objects (`principal_id`, `principal_type`, `public_key`), not bare strings.

Python `grant(subject="agent:deploy")` expands a string into a Principal (type inferred from the prefix before `:`, default `agent`) and generates a keypair if the application did not supply one. Private keys stay on the in-memory `Principal` / process keyring. They are never serialized. Pigeon is not a key custodian.

## Ambiguities and conservative resolutions

1. **How does `verify` see the chain if `parent` is only an id?**
   Transmit ancestors in the Pass document. Reject a leaf without a resolvable parent. Do not add fields to Authority.

2. **How does `grant()` sign without an issuer in the tiny API?**
   If `issuer` is omitted, generate an ephemeral organization principal `issuer:root` in-process. Production callers should pass an explicit `Principal`.

3. **How does `delegate()` sign if Pigeon does not hold keys?**
   Sign with the parent subject's private key from the in-memory Principal/keyring, or with an explicit `signing_key`. After JSON round-trip, the caller must supply the key. That is intended.

4. **Bare numeric constraints in the README snippet.**
   Expand SDK sugar to explicit `{op, ...}` before signing. `max_deploys_per_hour: 3` becomes a `rate` on dimension `deploys`, `max=3`, `window_seconds=3600`. A bare integer on any other key becomes `max` on that dimension.

5. **Floats and canonical numbers.**
   Reject non-integers in signed payloads (NaN, Infinity, decimals, `-0`). Integers must be in `[-(2^53-1), 2^53-1]`. This avoids JSON number interoperability traps. Examples use integer amounts.

6. **Rate windows that differ between parent and child.**
   Require identical `window_seconds` and `child.max <= parent.max`. If the windows differ, reject. Do not guess about density.

7. **Parent €100/hour, two children €100/hour each.**
   Evaluate `rate` and `count` against every ancestor, recording usage per authority id. Stateless ops (`eq`, `max`, …) are checked on the leaf only, because attenuation already proved they are ⊆ parent.

8. **Missing context value for a constraint.**
   Fail closed (`CONSTRAINT_VIOLATION`), except `rate`/`count` which default the increment to `1` (an invocation).

9. **Replay vs uniqueness.**
   Credential uniqueness: the first time an `id` is seen, remember its `nonce`. A later Pass with the same `id` and a different `nonce` is `REPLAY_DETECTED`. Same id+nonce is the same credential and may be reused until expiry/rate/count.
   Runtime replay: if `context["invocation_id"]` is present, reject duplicate `(authority_id, invocation_id)`.

10. **`*` resources.**
    Only legal on a root grant. A child may not contain `*`, even if the parent has `*`. Narrow `*` to a concrete pattern instead.

11. **Capability matching.**
    Exact string equality. No wildcards, no hierarchy.

12. **Maximum depth.**
    Default 8. Configurable on `delegate`/`verify`, not stored on the Authority (that would be an extra field). Tampered `delegation_depth` that is not parent+1 is `INVALID_DELEGATION`.

13. **`grant`/`delegate` failure mode.**
    Raise `DelegationError` with a reason code. `verify` never raises for a denied action; it returns a structured result.

14. **Clock.**
    `issued_at` / `expires_at` are UTC seconds with a `Z` suffix, no fractions, no offsets. `context["now"]` overrides the clock for tests. Valid while `now < expires_at`.

15. **Default TTL.**
    3600 seconds if `expires_at` is omitted. Short TTL is the practical revocation story for offline verifiers.

16. **Unknown fields / unknown constraint ops.**
    `MALFORMED_AUTHORITY`. Fail closed.

17. **`version`.**
    Integer `1` only.

18. **OR / NOT / regex.**
    Not in the primitive set. A verifier that cannot prove narrowing rejects.

19. **Subject type inference.**
    Prefix before the first colon: `human`, `agent`, `service`, `organization` (also `org` → `organization`). Otherwise `agent`.

20. **Why not Biscuit/UCAN/macaroons.**
    Answered in `SPEC.md`. Not revisited here.

## Implementation order

Project structure → authority → principal → canonicalization → signing → delegation → attenuation → verify/chain → replay → revocation → rate/count → tests → fixtures → examples → MCP → docs.
