<!-- SPDX-License-Identifier: Apache-2.0 -->
# SEAL-MEDIATION-PROFILE-L0

| | |
|---|---|
| **Profile** | `SEAL-MEDIATION-PROFILE-L0` |
| **Version** | `v0` |
| **Status** | `draft` |
| **Date** | 2026-06-30 |
| **License** | Apache-2.0 |

Licensed under the Apache License, Version 2.0 (see `../LICENSE`).

This profile defines what it means for an MCP tool-mediation boundary to be
**seal-conformant at level L0**, and specifies the canonical **decision receipt** a
conformant boundary emits. It is the written companion to the `seal-check` widget:
the widget is the executable demonstration of this profile, and every receipt field
documented here is mapped to its clause by the widget's **Conformance map** view.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted
as in RFC 2119.

> **Ground-truth rule.** This profile *documents* the receipt the kernel actually
> emits; it does not dictate it. Where this text and the live emitter disagree, the
> **emitter is authoritative** and this document is in error and MUST be corrected.

---

## §1 Scope & terminology

- **Boundary** — the point at which an MCP tool-call is admitted to or refused from a
  tool implementation.
- **Kernel** — the compiled, deterministic seal evaluator (a WebAssembly black-box in
  `seal-check`) that decides a single call against a trusted policy.
- **Decision** — one evaluation of one call (or one ordered trace) producing a
  verdict and a receipt.
- **seal-conformant (L0)** — a boundary that decides calls through the kernel under
  this profile's mediation contract (§2) and emits the canonical receipt (§4).

L0 covers **mediation of a supplied call against a supplied policy**, and the
disclosure discipline around that decision. Any higher layers beyond this
single-decision mediation are out of scope for L0 and are not described here.

---

## §2 Mediation contract

### §2.1 Default-deny (MUST)
The boundary MUST default to deny. A call is BLOCKED unless it is positively admitted
by §2.2. In particular, an unknown tool (not in the policy roster) and a known tool
with no matching, satisfied policy rule both MUST yield **BLOCK**.

### §2.2 Allow condition (MUST)
A call is **ALLOWED** if and only if **all** of the following hold; otherwise it is
**BLOCKED**:
1. **Parse witness valid** — the request parses to a canonical MCP `tools/call`
   (`input.request_line`, §4.2).
2. **Capability validated against policy** — a policy rule matches the call and every
   gating kernel (§3) that applies returns `allow` for it (e.g. a required approval
   target is present, a required quorum is met, an operation is convergent, no
   temporal prohibition fires). This is witnessed by `witness.certs` (§4.5).
3. **Canonical decision bytes produced** — the kernel emits canonical decision bytes
   (`emitted_bytes`, §4.4) deterministically (§5).

### §2.3 Verdicts (MUST)
`verdict` MUST be one of:
- `ALLOW` — admitted per §2.2 (the kernel forwards the call).
- `BLOCK` — refused (a gating kernel denied, or default-deny applied).
- `ERROR` — the input could not be evaluated (malformed request / kernel error). An
  `ERROR` is not an admission; a boundary MUST treat it as non-allow.

---

## §3 Kernel policy model

A decision is the conjunction of independent gating kernels. Each emits one cert
(§4.5). A call is denied if **any** applicable gate denies (default-deny, §2.1). L0
recognizes four public gates:

| Gate | State | Admits | Denies |
|---|---|---|---|
| **§3.1 safety** | stateless | a tool whose matching policy rule is satisfied (incl. a present, correct approval target for a guarded tool) | unknown tools, unmatched policy, guarded tools without a valid approval, deny-listed actions (e.g. self-`approve`) |
| **§3.2 consensus** | stateless | a high-stakes call whose required quorum (e.g. 2-of-3) has voted | high-stakes calls lacking quorum, even if individually approved |
| **§3.3 convergence** | stateless | a state-mutating op that is convergent (e.g. a CRDT op such as `orset.add`) | non-convergent ops that can silently diverge (e.g. a blind `assign`) |
| **§3.4 temporal** | **stateful** | a call permitted by the ordered event trace so far | a call forbidden after a triggering event (e.g. `db.execute` after `session.revoke`) — a stale-capability replay |

§3.1–§3.3 are **stateless**: the verdict depends only on the single call and the
policy. §3.4 is **stateful**: it depends on the ordered trace, so demonstrating it
requires a sequence (init once, decide per step). `input.now` (§4.2) is the logical
clock over that trace.

Gates not applicable to a given call simply do not deny it; only applicable gates
appear (or matter) in `witness.certs`.

---

## §4 Decision-receipt schema (canonical)

> **SUPERSEDED (2026-07-04) — schema v1.** The receipt format described in
> this section (`seal_check_receipt: "v0"`, Schema K) is retired. The widget
> now emits the family-wide canonical **schema v1** receipt
> (`seal_receipt: "v1"`), normatively specified in
> `seal-host/docs/DECISION-RECEIPT-SCHEMA.md`, implemented by the shared
> `receipt-format.js`. The v1 schema preserves this section's separation
> discipline — §6.2's identity/provenance split is now HARD (a v1
> `kernel_identity` carrying toolchain/axioms is invalid). This section is
> kept for the historical record of the v0 profile; the field-by-field
> documentation below describes receipts produced before the migration.

The canonical receipt is a JSON object. Below, every field is documented with its
type. The widget emits exactly this object — no more, no fewer, top-level keys. A
real, byte-exact BLOCK receipt is shown at the end of this section.

### §4.1 `seal_check_receipt` (string, MUST)
The receipt format/profile version. `"v0"` for this profile.

### §4.2 `input` (object, MUST)
The decided call, normalized.
- `request_line` (string) — the canonical JSON-RPC 2.0 `tools/call` that was decided.
- `now` (integer) — the **caller-supplied logical clock** for the decision. It is NOT
  wall-clock time (see §5).
- `approvals` (array of string) — the approval target hashes presented with the call,
  as lowercase **64-hex SHA-256 target commitments**.

### §4.3 `verdict` / `reason` / `deny_kernel`
- `verdict` (string, MUST) — `ALLOW` | `BLOCK` | `ERROR` (§2.3).
- `reason` (string, MUST) — human-facing summary. On deny: `"<kernel> kernel:
  <reason>"`. On allow: `"every gating kernel allows"`.
- `deny_kernel` (string | null, MUST) — the gate that denied (`safety` | `consensus` |
  `convergence` | `temporal`), or `null` when allowed.

### §4.4 `emitted_bytes` (string, MUST)
The **verbatim** output of the kernel's `seal_decide` — the canonical decision bytes.
seal-check treats this as an opaque, reproducible string and does not rewrite it. As
emitted by the L0 kernel it is itself a JSON object with these keys:
- `route` — `"forward"` (admit) | `"block"` (refuse) | `"passthrough"` (call is not
  mediated by the policy).
- `audit` — a JSON-**encoded** string: `{ certs:[…], epoch:int, tool:string,
  verdict:"allow"|"deny" }`. This is the authoritative audit; its `certs` are
  re-surfaced into `witness.certs` (§4.5) and its `verdict` into the top-level verdict.
- `response` — a JSON-encoded MCP/JSON-RPC response, present when the gate synthesizes
  one (e.g. an `isError` refusal on `block`); **absent on a plain `forward`**.
- `error` — present only on an evaluation error (`ERROR` verdict).

A conformant boundary MUST preserve `emitted_bytes` verbatim; it is the byte-level
artifact the determinism requirement (§5) is defined over.

### §4.5 `witness` (object, MUST)
- `certs` (array, MUST) — one entry per gating kernel that evaluated the call. Each is
  the **per-gate seal**:
  - `kernel` (string) — the gate (`safety` | `consensus` | `convergence` | `temporal`).
  - `verdict` (string) — `allow` | `deny` (lower-case; per gate).
  - `reason` (string) — the gate's reason (may be a coded hash, e.g. an expected
    approval target).
  - `certHash` (string) — the gate's seal: an FNV-1a 64-bit hash, as a decimal string.

The top-level verdict is `BLOCK` iff any cert's `verdict` is `deny` (§2.1, §3).

### §4.6 `kernel_identity` (object, MUST)
The identity of the binary that actually ran. This block is **self-verified in the
browser** (§6.1).
- `wasm_sha256` (string) — SHA-256 of the kernel wasm, hashed in-browser from the
  loaded bytes.
- `self_verified_in_browser` (boolean) — `true` iff the in-browser hash equalled the
  pinned constant.
- `note` (string) — disclosure text stating this is the only thing verified.

### §4.7 `asserted_provenance` (object, MUST)
Provenance the public Lean proofs **assert** about the kernel source. This block is
**NOT verified in the browser** and MUST be clearly labelled as such (§6.2).
- `verified_in_browser` (boolean) — MUST be `false`.
- `lean_toolchain` (string) — e.g. `leanprover/lean4:v4.28.0`.
- `axioms` (array of string) — the asserted axiom footprint, e.g. `["propext",
  "Classical.choice", "Quot.sound"]`.
- `note` (string) — disclosure text stating this is asserted, not verified, and not
  part of the hash.

### Canonical example (byte-exact BLOCK receipt, 2062 bytes)
```json
{
  "seal_check_receipt": "v0",
  "input": {
    "request_line": "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"database\":\"prod\",\"sql\":\"drop table users\"}}}",
    "now": 1000,
    "approvals": []
  },
  "verdict": "BLOCK",
  "reason": "safety kernel: 7653913048106253087",
  "deny_kernel": "safety",
  "emitted_bytes": "{\"audit\":\"{…certs…,\\\"epoch\\\":1,\\\"tool\\\":\\\"db.execute\\\",\\\"verdict\\\":\\\"deny\\\"}\",\"response\":\"{…isError refusal…}\",\"route\":\"block\"}",
  "witness": {
    "certs": [
      { "kernel": "safety",   "verdict": "deny",  "reason": "7653913048106253087", "certHash": "10880664185493056985" },
      { "kernel": "temporal", "verdict": "allow", "reason": "trace ok (1 events)",  "certHash": "14726304512526927726" }
    ]
  },
  "kernel_identity": {
    "wasm_sha256": "ebd17c14668176612c49f6e2940b23df82a2c1a7cdef6759f0d6276ae997e9d0",
    "self_verified_in_browser": true,
    "note": "Binary identity of the evaluator actually executed. Hashed in your browser from the loaded bytes and compared to a pinned constant. This is the ONLY thing verified here."
  },
  "asserted_provenance": {
    "verified_in_browser": false,
    "lean_toolchain": "leanprover/lean4:v4.28.0",
    "axioms": ["propext", "Classical.choice", "Quot.sound"],
    "note": "What the public Lean proofs ASSERT about the kernel source. NOT verified in your browser and NOT part of the hash above."
  }
}
```
(`emitted_bytes` is abridged above only for readability; the live receipt carries the
full verbatim bytes.)

---

## §5 Determinism (MUST)

The same input MUST yield a **byte-identical** receipt. "Input" is the triple
(`request_line`, `now`, `approvals`). `now` is a **caller-supplied logical clock**,
not wall-clock time — the kernel never reads a real clock — so a receipt is fully
determined by its recorded `input`. Re-running with the same recorded `input` (same
`now`) MUST reproduce identical `emitted_bytes` and an identical receipt; this is what
makes the byte-diff meaningful rather than a wall-clock artifact.

A third party reproduces a receipt by: serving the widget over an http(s) or
`localhost` origin, pasting the same `input`, and diffing the bytes; and by
re-verifying `kernel_identity.wasm_sha256` against the pinned constant (§6.1). A
conformant boundary SHOULD make the receipt downloadable to support this.

---

## §6 Kernel identity & provenance disclosure

### §6.1 Binary identity (MUST disclose)
A conformant boundary MUST disclose the SHA-256 of the kernel binary it ran
(`kernel_identity.wasm_sha256`) and MUST verify it in the client against a pinned
constant (`self_verified_in_browser`). This establishes *which binary produced the
decision*. It is the only claim in the receipt that is verified at decision time.

### §6.2 Asserted provenance (MUST NOT over-claim)
The Lean toolchain and axiom footprint (`asserted_provenance`) describe what the
public proofs **assert** about the kernel *source*. A conformant boundary:
- MUST mark these `verified_in_browser: false`;
- MUST NOT present the sha256 as proving the axioms or the proofs;
- MUST NOT blend toolchain/axioms into the binary hash.

The sha256 answers "which binary ran"; it does not answer "are the proofs sound". The
two are disclosed as separate, distinctly-labelled blocks.

---

## §7 Conformance levels & claim discipline

### What a "seal-checked boundary" asserts
For the **exact call supplied**, the verdict is the deterministic decision of the
identified, self-verified kernel binary, whose decision logic is the subject of public
Lean 4 proofs (modulo their stated assumptions and the disclosed axioms).

### What it MUST NOT assert (claim discipline, MUST)
A conformant boundary MUST NOT claim, or let its UI imply, any of:
- certification of a **whole MCP server**, its transport, its tool implementations, or
  that a deployment actually routes its calls through the gate;
- that the sha256 proves the axioms or the Lean proofs;
- any **third-party endorsement**. In particular **no ARIA endorsement, outcome,
  affiliation, or status** is claimed or implied. This copy MUST be true regardless of
  any ARIA process state.

### L0 conformance checklist
- **MUST** decide via the kernel under the §2 mediation contract (default-deny).
- **MUST** emit the canonical receipt (§4) with all listed fields.
- **MUST** be deterministic (§5).
- **MUST** disclose binary identity (§6.1) and label asserted provenance (§6.2).
- **MUST** observe the claim discipline (§7).
- **SHOULD** make the receipt downloadable and the kernel sha re-verifiable.
- **MAY** present additional human-facing explanation, provided it does not violate §7.

---

## §8 Changelog
- **v0 (2026-06-30, draft)** — initial profile: mediation contract, four-gate policy
  model, canonical receipt schema, determinism, identity/provenance disclosure, claim
  discipline.
