# Security

Pigeon bounds what a delegated agent may do along the dimensions you encoded in a Pass. It does not make agents safe in general. Read this file before you ship.

## What Pigeon does

- A child Pass cannot carry more effective authority than its parent. Expansion of capabilities, resources, constraints, expiry, or depth fails closed.
- Tampering with any signed field invalidates the signature.
- The whole chain is verified, not just the leaf.
- Rate and count constraints are part of the protocol. A numeric cap that is not also a count can be spent over and over. If you need a budget, write a `count` (or a `rate`).
- Revoking any authority in a chain invalidates descendants, for verifiers that actually query a revocation store.

## What Pigeon does not protect against

**Prompt injection.** If an attacker can talk a model into calling a tool, Pigeon will allow the call whenever the Pass permits that tool, resource, and context. Pigeon bounds blast radius along the dimensions you encoded, and only those. It does not detect or prevent injection.

**Constraints you did not write.** An omitted dimension is not enforced. If you did not put `environment:production` out of reach, production is in reach. If you did not set a count, there is no remaining-budget check. The protocol will not invent a policy you did not sign.

**Offline revocation.** Offline verification cannot see revocations issued after the Pass was minted. A stolen Pass remains valid until `expires_at` for any verifier that does not consult a revocation store, and even a connected verifier only sees revocations that store contains. This is a real limitation. Mitigate it with short TTLs (see below), and by wiring a revocation store the verifier actually uses.

**Key management.** Pigeon does not generate your operational key hierarchy, does not store private keys, does not rotate them, and does not recover them. `pigeon keygen` prints a keypair to stdout. If you leak a subject private key, the holder can delegate anything that subject was allowed to delegate until expiry and revocation catch up.

**Same-process cryptography.** Inside a single trust boundary, where the issuer and the verifier are the same process, the signatures add little over a plain data structure check. The cryptography matters when a Pass crosses a process, a machine, or an organizational boundary. Do not pretend a signed object in local memory is stronger than the application that minted it.

**Anything outside the Pass.** Network policy, filesystem permissions, IAM roles, OAuth tokens, and the tools behind an MCP server are not Pigeon. A Pass that allows `read` on `database:customers` does not by itself talk to a database. The enforcement point (your tool server, your MCP middleware, your runner) must call `verify` and must refuse to act on a denial. If the runtime ignores the result, the Pass is decoration.

**Availability of stores.** In-memory replay, revocation, and usage stores vanish on process restart. After a restart, rate/count budgets reset and seen invocation ids are forgotten. That can be more permissive than you intended. If that matters, you need a store that survives the process. v0.1 does not ship one.

## Short TTL

Mint Passes that expire in minutes or a few hours, not weeks. Short TTL is the practical revocation mechanism for offline verifiers: a compromised Pass dies when `expires_at` hits, even if no revocation store is reachable.

Recommended default: one hour, which is what the reference `grant`/`delegate` use when you omit `expires_at`. Tighten it for high-impact capabilities (deploy, purchase, merge).

A child MUST expire no later than its parent. Do not "refresh" authority by delegating a later expiry. That is privilege escalation and is rejected.

## Fail closed

If the verifier cannot prove that a child is narrower, it rejects. If a constraint dimension is missing from context, it rejects. If a number is a float, it rejects. If a resource wildcard is not the single trailing-`*` form, it rejects. There is no best-effort allow.

## Replay

A Pass is reusable until expiry, rate, or count says otherwise. That is intentional: an agent may call `deploy` twice under a 3-per-hour cap.

Credential uniqueness detects the same `id` presented with a different `nonce` (a manufactured twin). Runtime replay detects a duplicate `context.invocation_id`. If you need one-shot invocations, supply `invocation_id`. If you omit it, reuse is not a replay.

## Rate and count across a chain

Rate and count are evaluated against every ancestor, not only the leaf. Two children that each look locally legal still cannot together exceed a parent budget. Stateless constraints (`eq`, `max`, …) are checked on the leaf; attenuation already proved they are at most the parent.

## Enforcement points

The MCP helpers in `pigeon.integrations.mcp` verify a Pass before a tool handler runs and return a structured denial on failure. They do not implement the MCP specification. They do not make a tool safe if you execute it anyway. Put them on the server that would otherwise run the tool.

## Reporting

This is v0.1. If you find a way for a child to exercise more effective authority than its parent, that is a protocol bug. Treat it as such.
