# Pigeon Authority Protocol v0.1

This document is the protocol. A correct implementation in any language can be written from this file alone. The Python package in this repository is a reference, not a second source of truth.

Pigeon Pass is its own credential format. It is not a profile of JWT, CWT, macaroons, Biscuit, or UCAN.

## 1. Purpose

A Pigeon Pass is a delegated authority credential. Identity says who a principal is. A Pass says what that principal may do, on which resources, under which constraints, until when.

Core invariant: a child authority must never contain more effective authority than its parent. If a verifier cannot prove that a child is narrower or equal, it MUST reject.

## 2. Version

`version` is the integer `1`. Any other value is malformed.

## 3. Principal

A principal is an object with exactly these fields, and no others:

| Field | Type | Meaning |
|---|---|---|
| `principal_id` | string | Stable identifier, e.g. `human:alice`, `agent:deploy`, `service:ci` |
| `principal_type` | string | One of `human`, `agent`, `service`, `organization` |
| `public_key` | string | Ed25519 public key, 32 bytes, unpadded base64url |

Unknown `principal_type` values are malformed. Empty `principal_id` is malformed. Private keys NEVER appear in a Pass.

## 4. Authority schema

An Authority is an object with exactly these fields, and no others:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Unique identifier of this authority (UUID string recommended) |
| `version` | integer | Protocol version. Must be `1` |
| `issuer` | Principal | Who signed this authority |
| `subject` | Principal | Who may exercise this authority |
| `parent` | string or null | Parent authority `id`, or `null` for a root grant |
| `capabilities` | array of string | Opaque action names |
| `resources` | array of string | Opaque resource patterns |
| `constraints` | object | Map of dimension name to constraint expression |
| `issued_at` | string | UTC timestamp |
| `expires_at` | string | UTC timestamp, strictly after `issued_at` |
| `nonce` | string | Unique per `id`. Non-empty |
| `delegation_depth` | integer | `0` at the root. Each child is parent depth plus one |
| `signature` | string | Ed25519 signature, unpadded base64url |

Unknown fields are malformed. Missing fields are malformed.

### 4.1 Capabilities

Opaque strings. Exact match only. No wildcards, no hierarchy, no ontology.

A child capability set MUST be a subset of the parent capability set.

Empty arrays are legal. They authorize no actions.

Before signing, implementations MUST sort capabilities lexicographically by UTF-8 byte order and strip duplicates.

### 4.2 Resources

Opaque identifiers, for example `database:customers`, `repo:acme/api`, `environment:staging`, `mcp:github`.

A single wildcard form is defined: a trailing `*` matches any suffix. `merchant:*` matches `merchant:example` and `merchant:example:eu`. `*` as the entire pattern matches every resource and is permitted ONLY on a root grant (`parent` is `null`). A child MUST NOT contain `*`.

`*` may appear only as the final character of a pattern. `*foo` and `foo*bar*` are malformed.

Before signing, implementations MUST sort resources lexicographically by UTF-8 byte order and strip duplicates.

Matching:

- pattern `P` with no trailing `*`: matches only the string `P`
- pattern `P*`: matches any string that starts with `P`
- pattern `*`: matches any string

Attenuation: every child pattern MUST be provably narrower than or equal to at least one parent pattern. Pattern `C` is narrower than or equal to pattern `P` iff every string that matches `C` also matches `P`.

Consequences:

- `merchant:*` → `merchant:example` is valid
- `merchant:example` → `merchant:*` is invalid
- `merchant:*` → `merchant:*` is valid (equal)
- `environment:staging` → `environment:production` is invalid
- parent `*` (root only) → any non-`*` child pattern is valid
- if narrowing cannot be proven, reject

### 4.3 Constraints

`constraints` is an object. Keys are dimension names (non-empty strings). Values are constraint expressions. Logical AND is implicit across keys. There is no OR and no NOT.

A constraint expression is an object with an `op` field. Unknown ops are malformed. Unknown fields on an expression are malformed.

| `op` | Fields | Meaning at verify time |
|---|---|---|
| `eq` | `value` | `context[dimension]` must equal `value` |
| `neq` | `value` | `context[dimension]` must not equal `value` |
| `max` | `value` (integer) | `context[dimension]` is an integer `<= value` |
| `min` | `value` (integer) | `context[dimension]` is an integer `>= value` |
| `in` | `values` (non-empty array) | `context[dimension]` equals one element of `values` |
| `prefix` | `value` (non-empty string) | `context[dimension]` is a string starting with `value` |
| `suffix` | `value` (non-empty string) | `context[dimension]` is a string ending with `value` |
| `rate` | `max` (positive integer), `window_seconds` (positive integer) | cumulative increment for this dimension over the last `window_seconds` seconds, plus this call, must be `<= max` |
| `count` | `max` (positive integer) | cumulative increment for this dimension over the life of this authority, plus this call, must be `<= max` |

`value` for `eq`/`neq`/`in` items MUST be a string, an integer, a boolean, or null. Nested objects and arrays are malformed. Floats are malformed.

For `rate` and `count`, the increment is `context[dimension]` if present, otherwise `1`. The increment MUST be a positive integer. These two ops are stateful. Implementations MUST record usage against **every** authority in the chain, not only the leaf, so two children cannot together exceed a parent budget.

All other ops are stateless and are evaluated on the leaf only (attenuation already proved they are ⊆ the ancestors). If a stateless constraint's dimension is missing from `context`, the verifier MUST reject with `CONSTRAINT_VIOLATION`. Never treat absence as a match.

Before signing, implementations MUST:

- sort constraint object keys lexicographically
- sort `in.values` by the canonical JSON of each element

#### Constraint attenuation

Every parent dimension MUST appear in the child. Extra child dimensions are allowed (they only narrow). Removing a parent dimension is rejected.

For each shared dimension, the child expression MUST be provably narrower than or equal to the parent. If the verifier cannot prove it, it MUST reject. Never guess.

Same-op rules:

- `eq`: values must be equal
- `neq`: values must be equal (same excluded value)
- `max`: `child.value <= parent.value`
- `min`: `child.value >= parent.value`
- `in`: `child.values` is a subset of `parent.values`
- `prefix`: `child.value` starts with `parent.value`
- `suffix`: `child.value` ends with `parent.value`
- `rate`: `child.window_seconds == parent.window_seconds` AND `child.max <= parent.max`. Different windows are rejected even if density would be lower
- `count`: `child.max <= parent.max`

Cross-op rules that MAY be accepted because they are provable:

- parent `neq X`, child `eq Y` where `Y != X`
- parent `in S`, child `eq V` where `V` is in `S`
- parent `prefix P`, child `eq V` where `V` is a string starting with `P`
- parent `suffix S`, child `eq V` where `V` is a string ending with `S`
- parent `max M`, child `eq V` where `V` is an integer `<= M`
- parent `min M`, child `eq V` where `V` is an integer `>= M`

Every other cross-op combination is rejected.

### 4.4 Timestamps

`issued_at` and `expires_at` are UTC timestamps with second precision and a `Z` suffix:

```
YYYY-MM-DDTHH:MM:SSZ
```

No fractional seconds. No numeric offsets. `expires_at` MUST be strictly after `issued_at`. An authority is expired when `now >= expires_at`. It is valid while `now < expires_at`.

A child `expires_at` MUST be less than or equal to the parent `expires_at`.

### 4.5 Depth

Root: `parent` is `null` and `delegation_depth` is `0`.

Child: `parent` is the parent `id` and `delegation_depth` is parent depth plus one.

Default maximum depth is `8`. Implementations MAY make the maximum configurable at verify/delegate time. It is not a field on the Authority. Depth greater than the maximum is `INVALID_DELEGATION`. A depth that is not parent+1 is `INVALID_DELEGATION`.

## 5. Pass document

An Authority does not embed its ancestors. The transmissible document is:

```json
{"authorities":[<leaf>,<parent>,...,<root>]}
```

The array MUST be ordered leaf first, root last. The last element's `parent` MUST be `null`. For every adjacent pair, `authorities[i].parent == authorities[i+1].id`. An implementation that receives a leaf without a resolvable parent MUST reject (`INVALID_PARENT`).

The Pass document as a whole is not signed. Each Authority in the array is signed independently.

## 6. Canonical serialization

Signing and signature verification operate on the canonical UTF-8 bytes of the Authority object **without** the `signature` field.

A future TypeScript, Go, or Rust implementation MUST produce identical bytes from this section.

### 6.1 Encoding

- Output is UTF-8.
- There is no insignificant whitespace: no spaces, no newlines, no trailing commas.
- Object keys are sorted lexicographically by UTF-8 byte order at every nesting level.
- Arrays preserve the order given to the serializer. Callers MUST pass capabilities, resources, and `in.values` already sorted as specified above.

### 6.2 Types

- `null` → `null`
- `true` / `false` → `true` / `false`
- strings: JSON strings with the escaping rules below
- integers: decimal, no leading plus, no leading zeros (`0` is `0`, not `00`). Reject integers outside `[-(2^53-1), 2^53-1]`. Reject `-0`; serialize zero as `0`.
- floating-point numbers, NaN, and Infinity are REJECTED. They MUST NOT appear in a signed payload.
- objects and arrays as above
- any other type is REJECTED

Python `bool` is not an integer. `true` and `1` are distinct.

### 6.3 String escaping

Inside a JSON string:

- `"` → `\"`
- `\` → `\\`
- U+0008 → `\b`
- U+0009 → `\t`
- U+000A → `\n`
- U+000C → `\f`
- U+000D → `\r`
- other code points U+0000–U+001F → `\u00xx` with lowercase hex
- solidus `/` is NOT escaped
- U+0020 and above (including non-ASCII) are emitted as UTF-8, not `\uXXXX`

### 6.4 Example

Unsigned payload (pretty-printed here only for reading; the signed bytes have no whitespace):

```json
{
  "capabilities": ["deploy"],
  "constraints": {},
  "delegation_depth": 0,
  "expires_at": "2026-01-02T00:00:00Z",
  "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "issued_at": "2026-01-01T00:00:00Z",
  "issuer": {
    "principal_id": "human:alice",
    "principal_type": "human",
    "public_key": "<base64url>"
  },
  "nonce": "11111111111111111111111111111111",
  "parent": null,
  "resources": ["environment:staging"],
  "subject": {
    "principal_id": "agent:deploy",
    "principal_type": "agent",
    "public_key": "<base64url>"
  },
  "version": 1
}
```

Canonical key order of the unsigned object is: `capabilities`, `constraints`, `delegation_depth`, `expires_at`, `id`, `issued_at`, `issuer`, `nonce`, `parent`, `resources`, `subject`, `version`.

After signing, `signature` is inserted. Canonical key order of the full object places `signature` between `resources` and `subject`.

## 7. Cryptography

Ed25519 as specified in RFC 8032. Implementations MUST use a well-reviewed library. Do not implement the primitive by hand.

- Public key: 32 bytes, unpadded base64url
- Private key: 32 bytes, unpadded base64url. Never serialized into a Pass
- Signature: 64 bytes, unpadded base64url

Let `payload` be the canonical bytes of the Authority without `signature`. `signature = Ed25519Sign(issuer_private_key, payload)`. Verification uses `issuer.public_key`.

A root is signed by its `issuer`. A child is signed by the parent `subject` (who becomes the child `issuer`). The application holds private keys. Pigeon is not a key custodian.

Unpadded base64url is RFC 4648 base64url with padding `=` characters stripped. Decoding MUST accept missing padding.

## 8. Minting

### 8.1 Root grant

Construct an Authority with `parent` null, `delegation_depth` 0. Normalize capabilities, resources, constraints. Set `issued_at` / `expires_at`. Generate `id` and `nonce`. Canonicalize the unsigned object. Sign with the issuer private key. Attach `signature`.

### 8.2 Delegate

In this order:

1. Validate the parent (schema, signature, not expired).
2. Validate requested capabilities, resources, and constraints.
3. Enforce attenuation (capabilities subset, resources narrower or equal, constraints narrower or equal, expiry not later than parent).
4. Reject if parent depth + 1 exceeds the maximum.
5. Create the child with `parent` set to the parent `id`, `issuer` equal to the parent `subject` (same `principal_id`, `principal_type`, and `public_key`), `delegation_depth` = parent depth + 1.
6. Sign the child with the parent subject's private key.
7. Return the child together with the ancestor chain (parent, then the parent's ancestors).

A child MUST NOT be able to self-authorize a broader Pass. There is no path that signs a child with a key other than the parent subject's key and still verifies.

## 9. Verification algorithm

Inputs: a Pass document (or an Authority plus ancestors), `action` (string), `resource` (string), `context` (object), current time, optional replay store, optional revocation store, optional usage store, optional max depth (default 8).

`verify` returns a structured result, never a bare boolean:

```
{
  "allowed": boolean,
  "reason_code": string or null,
  "message": string,
  "details": object
}
```

On success `reason_code` is null. On failure `details` MUST include the concrete comparison (requested value, allowed value, which constraint, which chain index) where that is applicable.

Algorithm. Stop at the first failure.

1. Parse the Pass. Unknown fields, bad types, bad timestamps, unsupported version → `MALFORMED_AUTHORITY`.
2. Reconstruct the chain, leaf first. Missing parent of a non-root → `INVALID_PARENT`. Chain that does not end at a root (`parent` null, depth 0) → `INVALID_PARENT`. Adjacent parent ids that do not match → `INVALID_PARENT`.
3. If leaf `delegation_depth` > max depth → `INVALID_DELEGATION`.
4. For each link from leaf to root:
   1. If its `id` is in the revocation store → `REVOKED` (revoking any link invalidates descendants).
   2. If `now >= expires_at` → `EXPIRED`.
   3. If the signature over the canonical unsigned bytes is invalid → `INVALID_SIGNATURE`.
5. For each child/parent adjacent pair:
   1. Child `delegation_depth` must equal parent depth + 1 → else `INVALID_DELEGATION`.
   2. Child `issuer` must equal parent `subject` (id, type, and public key) → else `INVALID_ISSUER`.
   3. Child must attenuate relative to parent → else `PRIVILEGE_ESCALATION`.
6. Credential uniqueness: remember `(id, nonce)` for the leaf. If this `id` was previously seen with a different `nonce` → `REPLAY_DETECTED`. Same id and nonce is the same credential and may be reused until expiry, rate, or count says otherwise.
7. Runtime replay: if `context.invocation_id` is a non-empty string and that pair `(leaf id, invocation_id)` was already recorded → `REPLAY_DETECTED`. If the field is absent, skip this check.
8. If `action` is not in the leaf `capabilities` → `CAPABILITY_NOT_GRANTED`.
9. If `resource` matches none of the leaf resource patterns → `RESOURCE_NOT_ALLOWED`.
10. Evaluate stateless leaf constraints against `context` → `CONSTRAINT_VIOLATION` on failure.
11. For every authority in the chain, evaluate `rate` and `count` against the usage store and `context`. Rate failure → `RATE_LIMIT_EXCEEDED`. Count failure → `CONSTRAINT_VIOLATION`.
12. Record rate/count usage for every chain link. Record `invocation_id` if present.
13. Allow.

Implementations SHOULD expose the chain so a developer can inspect each hop (id, issuer, subject, depth, capabilities, resources, expiry, signature validity).

## 10. Reason codes

| Code | When |
|---|---|
| `INVALID_SIGNATURE` | Ed25519 verify failed on any link |
| `EXPIRED` | `now >= expires_at` on any link |
| `INVALID_ISSUER` | Child issuer is not the parent subject |
| `INVALID_PARENT` | Missing, mismatched, or non-root-terminating chain |
| `CAPABILITY_NOT_GRANTED` | `action` is not in the leaf capability set |
| `RESOURCE_NOT_ALLOWED` | `resource` matches no leaf pattern |
| `CONSTRAINT_VIOLATION` | Stateless constraint failed, or count exceeded |
| `PRIVILEGE_ESCALATION` | A child is not provably ≤ its parent |
| `INVALID_DELEGATION` | Depth error or structurally illegal delegation |
| `REPLAY_DETECTED` | Duplicate credential identity or duplicate `invocation_id` |
| `RATE_LIMIT_EXCEEDED` | A `rate` constraint would be exceeded |
| `REVOKED` | An authority id in the chain is revoked |
| `MALFORMED_AUTHORITY` | Schema, types, version, or canonicalization rejected the input |

## 11. Replay store

Two separate concepts:

1. **Credential uniqueness.** Map `authority_id → nonce`. The first observation records the pair. A later observation of the same id with a different nonce is `REPLAY_DETECTED`.
2. **Runtime replay.** Set of `(authority_id, invocation_id)`. Used only when the caller supplies `invocation_id` in context.

An in-memory implementation is sufficient for v0.1. The interface must be implementable by Redis or a database later. This specification does not define those backends.

## 12. Revocation store

Interface: `revoke(authority_id)` and `is_revoked(authority_id)`.

During chain verification, if any link is revoked, the result is `REVOKED`. Revoking an ancestor invalidates all descendants because every descendant is checked through that ancestor.

Revocation is not a service. It is a local interface. See `SECURITY.md` and section 13.

## 13. Short TTL and offline verification

Passes SHOULD be minted with a short `expires_at` (minutes to a few hours, not weeks). Short TTL is the practical control when the verifier is offline.

Offline verification cannot see revocations issued after the Pass was minted. A verifier that never consults a revocation store will accept a revoked-but-unexpired Pass. That is a real limitation, not an edge case. Combine short TTL, chain checks, and a revocation store that the verifier actually queries.

## 14. Conformance fixtures

The `fixtures/` directory contains JSON cases with input, expected `allowed`/`success`, and expected `reason_code`. A second implementation MUST produce the same reason codes for these cases. Regeneration of the fixtures MUST be byte-identical.

## 15. Relationship to prior art

Macaroons, Biscuit, and UCAN all solve a nearby problem: attenuable, delegable authorization that does not require a central check at every hop.

**Macaroons** (Google, 2014) are bearer credentials with caveats. Attenuation is appending caveats. They are elegant for service-to-service narrowing and support third-party caveats. HMAC-chained constructions are operationally simple when there is a shared root secret. They are not designed around an agent-native constraint set, and the HMAC model assumes a secret held by the discharging service rather than a public-key chain of distinct principals.

**Biscuit** (Clever Cloud) is a public-key, Datalog-based authorization token. It is powerful: policies can express rich logic, public-key attenuation is first-class, and offline verification is real. That power is the mismatch. Datalog makes Biscuit a policy language. Pigeon deliberately refuses a policy language. The v0.1 constraint set is closed so a verifier can prove narrowing by construction, or reject. There is no predicate the caller can invent.

**UCAN** (Fission / UCAN working group) puts capability delegation on a chain of proofs, typically over DID-identified issuers, with JWT/CWT encodings. It is a good fit for user-owned capabilities on the web. Pigeon does not use JWT or CWT, does not require DIDs, and does not treat "who is this" as the interesting problem. Identity is assumed to exist elsewhere. The interesting problem is bounding what an already-identified agent may do, including rate and count, when it spawns a child.

Pigeon defines its own format because:

1. The constraint model is agent-native (capabilities, resources, rate, count) rather than caveats, Datalog facts, or JWT claims.
2. The primitive set is deliberately small and closed. No regex, no OR, no NOT, no Datalog.
3. Attenuation is fail-closed: unprovable narrowing is a reject, not a maybe.
4. The serialization is specified to the byte so a Pass minted in Python verifies in another language from this document alone.

These systems do their jobs well. Pigeon is smaller on purpose.
