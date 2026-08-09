<!-- VENDORED COPY. Upstream normative source: seal-host/docs/DECISION-RECEIPT-SCHEMA.md
     (public). Copied into seal-check so the v1 schema cited by receipt-format.js,
     receipt.js, kernel.js and the L0 profile is reachable without another repository checkout.
     Keep in sync with upstream; upstream wins on any divergence. -->

<!-- SPDX-License-Identifier: Apache-2.0 -->

# Decision-Receipt Schema v1 (normative)

**Status: v1 CONVERGED (Day-2 complete, 2026-07-04).** The Day-1 freeze was
reviewed and passed; the two parked decisions were ruled: (1) neutral
discriminator `seal_receipt: "v1"` adopted; (2) **hard split** of
`kernel_identity` vs asserted provenance, with `v0-live` grandfathered.
Producers and verifiers in seal-check and seal-assurance-kit now emit/accept
this schema (§10 records what landed). Serialization/format consolidation
only: nothing here changes the wasm binary, its pin, any Lean proof, or any
decision logic.

This document is the single normative definition of the JSON **decision
receipt** produced and verified across the seal family. It exists because
three incompatible dialects drifted into production:

| Dialect | Producer | Verifier | Fate under v1 |
|---|---|---|---|
| Schema K (`seal_check_receipt`) | `seal-check/kernel.js buildReceipt` | `seal-assurance-kit src/verify.cjs` (augmented as "kit receipt") | **Retired.** Producers converge to v1. Verifiers reject K with a clear "legacy" error. |
| Schema L (`seal_live_receipt`) | `seal-live-demo/seal-gateway/decide.cjs` | `seal-check/receipt.js` | **Adopted as v1** (generalised; L receipts remain valid as `v0-live`). |
| Host audit line | `seal-host/Host/Audit.lean` | `seal-host/scripts/seal_log.mjs` | **Not a receipt.** Distinct artifact — see §8. |

## 1. Canonical shape (v1 = Schema L, generalised)

A v1 receipt is a single JSON object. Version discriminator:

```
"seal_receipt": "v1"
```

Verifiers MUST also accept the legacy discriminator `"seal_live_receipt":
"v0"` with identical field semantics (`v0-live`; the deployed live-demo
gateway keeps emitting it until its own audited bump). The Schema K
discriminator `"seal_check_receipt"` is NOT v1-compatible; verifiers MUST
reject it as legacy, naming this spec.

> **Decision (ruled at Day-1 review):** the neutral discriminator
> `seal_receipt: "v1"` is adopted; producers do not spread the
> `seal_live_receipt` key beyond the deployed gateway that already emits it.

### Field table

| Field | Type | Required | Semantics |
|---|---|---|---|
| `seal_receipt` | `"v1"` | yes (or legacy `seal_live_receipt:"v0"`) | schema version discriminator |
| `tool` | string | yes | mediated tool name (e.g. `"db.execute"`) |
| `arguments` | object | yes | the tool-call arguments, verbatim; key order is fixed at production time and is significant (§2) |
| `now` | integer ≥ 0 | optional (default 1000) | the caller-supplied **logical clock** the kernel decided with — carried so re-derivation replays the same clock; NOT wall time |
| `canonical_request` | string | optional | the exact canonical request line that was hashed; if present it MUST equal the line derived per §2 |
| `canonical_request_sha256` | 64-hex string | yes | SHA-256 of the canonical request line (§2) |
| `bypass` | boolean | yes | `true` = mediation was skipped (control run); §6 |
| `verdict` | `"ALLOW" \| "BLOCK" \| "ERROR"` | yes | §5 vocabulary |
| `reason` | string | yes | human-readable ground for the verdict |
| `deny_kernel` | string or null | yes when mediated | which gating kernel denied (null on ALLOW) |
| `certs` | array | yes when mediated | per-gate seals `{kernel, verdict, reason, certHash}` with `certHash` a **decimal string** (u64; §3) — top-level, not nested under `witness` |
| `emitted_bytes` | string | yes when mediated | verbatim canonical `seal_decide` output |
| `kernel_identity` | object | yes | `wasm_sha256` (64-hex, or **null iff `bypass`**), `self_verified` (boolean). HARD SPLIT: never carries toolchain/axioms in v1. See §4 |
| `asserted_provenance` | object | optional | asserted-not-verified proof hygiene (`lean_toolchain`, `axioms`, `verified_in_browser` — MUST NOT be `true`); the only v1 home for toolchain/axioms (§4) |
| `signed_config` | object | yes when mediated in v2 | exact `{payload, signature, pubkey}` supplied to `seal_init`; payload is the signed compact JSON string, signature is 128-hex Ed25519, pubkey is 64-hex |
| `kernel_config` | object | yes when mediated | the exact trusted config the kernel was initialised with — re-derivation input |
| `granted_capabilities` | array of objects | yes when mediated | the presented grants. Two entry forms (§3): **un-hashed** `{tool, <policy-selected fields>...}` when the producer holds the grant pre-image, or **opaque** `{target: "<64 lowercase hex>"}` when it does not (e.g. seal-check's fire-your-own box accepts raw targets) |
| `policy_id` | string | optional | producer's policy label |
| `signature` | object | optional | integrity envelope (e.g. live-demo HMAC demo key); never a substitute for re-derivation |

Producer-local trailing blocks (live-demo's `execution`, `gateway`) are
permitted; verifiers MUST ignore unknown top-level fields except verifier-only
authority claims such as `authority_trusted`, which MUST be rejected.

## 2. `canonical_request_sha256` — exact pre-image

The canonical request line is:

```js
JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
                 params: { name: <tool>, arguments: <arguments> } })
```

with `<tool>` = the receipt's `tool` and `<arguments>` = the receipt's
`arguments` object serialised **in its stored key order** (JS objects
preserve insertion order for non-integer-like keys; integer-like argument
names are forbidden in v1 for this reason). The hash is SHA-256 over the
UTF-8 bytes of that line, lowercase hex.

This single function subsumes both prior dialects — the divergence was never
the shape, only what was fed in:

* Schema K's `input.request_line` was already exactly this line for the
  receipt's own `(tool, args)` (`seal-check/seal-config.js` `rpc()`).
* Schema L hardcoded `name: "db.execute"`; v1 generalises `name` to `tool`.
  For every existing L receipt the bytes are unchanged.

**Verifier obligation (closes drift (c)):** a verifier MUST derive this line
from the SAME `(tool, arguments)` it feeds the kernel for re-derivation —
never hash one stored string while re-deriving from a different field. If
the receipt carries `canonical_request`, the verifier MUST check it equals
the derived line before hashing.

Frozen test vectors (also enforced by `test/receipt-format.test.cjs` in
seal-check and `test/format-check.cjs` in seal-assurance-kit):

| # | tool | arguments | sha256 |
|---|---|---|---|
| V1 (real live-demo receipt, `evidence/receipts.jsonl` line 1) | `db.execute` | `{"operation":"insert","table":"staging_deploy_audit","payload":"{\"deploy_ref\":\"deploy-2026-06-30\"}"}` | `66330ea2242d45a5a6b32d85007464125608fec7e88430fa3c23d5c5303db756` |
| V4 (kit block fixture, `fixtures/receipt-block.json`) | `db.execute` | `{"database":"prod","sql":"drop table users"}` | `460d746ba064ab9398885158dddfd6d32f1722b0efe0d3b6085c8441e9127793` |

V4 is the proof of convergence: the kit's stored Schema-K
`canonical_request_sha256` is byte-identical to what the v1 function
produces.

## 3. Capability targets — one convention, policy-determined arity

Approval targets are computed by the JS mirror of Lean `Seal.stableHashParts`:

```
encoded := parts.map(p => `${charCount(p)}:${p}`).join("")
target := SHA-256(UTF-8(encoded)) as 64-character lowercase hex
```

`charCount` is the JavaScript/Lean string character count, not UTF-8 byte
length. For non-ASCII, the bytes hashed are still the UTF-8 bytes of the
netstring text.

**The convention (pinned):**

```
target = stableHashParts([ tool, ...parts ])
```

where `parts` are the policy's `target` spec entries resolved **in policy
order** — each `{literal: s}` contributes `s`, each `{arg: a}` contributes
the call's argument value `a`. The prior "arity mismatch" (2-part vs 3-part)
was two policies, not two conventions: arity is policy-determined and both
existing uses already follow this rule.

Frozen vectors:

| # | policy target spec | encoded parts | target hex |
|---|---|---|---|
| V2 | `[{literal:"store"}]` (seal-check `store.update`) | `12:store.update5:store` | `6bff1759cf3c00f781f0b15d428f4cf84e59f8b10be48dd4dd742175a3e6f984` |
| V2b | `[{literal:"pay"}]` (seal-check `payments.send`) | `13:payments.send3:pay` | `e35dd14f3e1d02fec3b03a781b7f8928bfd1ce7b7f93a23a7b61228c536bd73a` |
| V3 | `[{arg:"table"},{arg:"operation"}]` (live-demo `db.execute`) | `10:db.execute20:staging_deploy_audit6:insert` | `351f47a44bcf935c7242432e24bd11db1536d7c1da873f0ca953c8b80ae02433` |

A v1 receipt carries grants in `granted_capabilities`, in one of two entry
forms, and the verifier resolves them via the shared
`capabilityTargetsFromPolicy(kernel_config, grants)`:

* **Un-hashed** `{tool, <fields>...}` — the strong form; the producer held
  the grant pre-image. The verifier recomputes the target from the POLICY's
  target spec for that tool: `{literal}` parts come from the policy itself,
  `{arg}` parts from the entry's field of that name, in policy order.
* **Opaque** `{target: "<64 lowercase hex>"}` — the producer did not hold the
  pre-image (e.g. a raw target pasted into seal-check's fire-your-own box).
  The verifier uses the target verbatim and COUNTS it: verdict
  re-derivation still holds, but the grant binding cannot be independently
  checked for that entry. Receipts say what the producer actually knew —
  opaque entries are honest, not equivalent.

## 4. `kernel_identity` and asserted provenance

Required keys: `wasm_sha256` (SHA-256 hex of the exact wasm binary the
producer executed; **null iff `bypass`**) and `self_verified` (boolean —
whether the producer hashed the loaded bytes against its pin). The key name
is `self_verified` (Schema L); Schema K's `self_verified_in_browser` is
retired with K.

Toolchain/axiom provenance (`lean_toolchain`, `axioms`) is ASSERTED, not
verified by any receipt consumer. **HARD SPLIT (ruled at Day-1 review, per
the L0 mediation profile §6.2,
`seal-check/docs/SEAL-MEDIATION-PROFILE-L0.md`):** in v1 these keys are
FORBIDDEN inside `kernel_identity` — a v1 receipt carrying them there is
invalid (`validateReceipt` rejects it). Their only v1 home is the separate
`asserted_provenance` block, whose `verified_in_browser` MUST NOT be `true`.
Legacy `v0-live` receipts with the merged block are grandfathered: verifiers
accept them as v0-live and base nothing on those fields either way.

The current private verified wasm pin (`a6a73fa5d3abc21bcca261b56aa6355705670fd55cdfb194a4bb344e69ba9e35`)
is not changed by this receipt schema; the pending audited public repin
(`docs/CONFORMANCE-BRIDGE.md`) is a separate step.

## 5. Verdict vocabulary

Receipts use exactly `ALLOW | BLOCK | ERROR`. Mapping from the kernel wire:

| kernel output | receipt verdict |
|---|---|
| `route: "forward"` | `ALLOW` |
| `route: "passthrough"` (not a mediated call) | `ALLOW` (reason says passthrough) |
| `route: "block"` (audit verdict `deny`) | `BLOCK` |
| `error` | `ERROR` |

The host audit line (§8) uses lowercase `allow`/`deny`; the normative map is
`allow → ALLOW`, `deny → BLOCK`. `DENY` never appears in a receipt.

## 6. Bypass receipts

`bypass: true` records that mediation was deliberately skipped (the seal-off
control). Requirements: `kernel_identity.wasm_sha256 = null`,
`self_verified = false`, no `kernel_config`/`emitted_bytes`/`certs`
obligations. A verifier MUST report a bypass receipt as **NOT MEDIATED** —
it is not "verified", and its `ALLOW` is not a kernel verdict. (The kit's
`seal verify` currently has no bypass branch; that is a Day-2 convergence
item.)

## 7. Verifier obligations (summary)

0. Validate the shape FIRST (`validateReceipt`): version discriminator,
   field table, hard split, stored-line-vs-derived-line equality. A
   malformed receipt never reaches the kernel. Pass the **received document
   text**, not a parsed object — §12.6; only then are the wire ambiguities
   `JSON.parse` collapses (duplicate discriminator members above all)
   visible at all.
1. `kernel_identity.wasm_sha256` equals the verifier's own hash of the
   binary it will re-run, and that binary matches the audited pin.
2. Derive the canonical line from the same `(tool, arguments)` used for
   re-derivation; check stored `canonical_request` (if present) equals it;
   hash and compare to `canonical_request_sha256`.
3. Require byte-identical compact reconstruction of `signed_config.payload`,
   byte equality between that payload and `JSON.stringify(kernel_config)`, and
   (for approval receipts) `approval.policy_hash = SHA256(payload)`. Surface
   its non-negative integer `epoch`; this carries freshness but does not enforce rollback.
4. Resolve `granted_capabilities` from the authenticated policy; call the
   pinned wasm's `seal_init` with the receipt's exact envelope and pubkey, then
   require verdict and emitted-byte equality. Never re-sign in the verifier.
5. Compute signer authority only from an independently supplied expected-key pin.
6. Handle `bypass` per §6: report NOT MEDIATED, never "verified".
7. Reject `seal_check_receipt` objects as legacy Schema K.

## 8. The host audit line is NOT a decision receipt

`seal-host/Host/Audit.lean` emits `{epoch, tool, verdict, certs}` (verdict
lowercase `allow`/`deny`) per decision; `seal-host/scripts/seal_log.mjs`
chains those lines with `SHA256(prevHead ‖ 0x1f ‖ payload)` (the in-Lean
demonstration instance uses FNV — documented in
`docs/VERIFIABLE-RECORD.md`). Different fields, different purpose (tamper
evidence over a trace, not per-call re-derivability), different hash
primitive. Nothing in this spec restructures it; the only bridge is the
verdict map in §5 and the shared `certs` entry shape (§1). Tools MUST NOT
present an audit line as a receipt or vice versa.

## 9. Shared implementation (the frozen seam)

One module implements §2, §3 and §5 for every JS producer/verifier:

* **Canonical source:** `seal-check/receipt-format.js` (pure ES module,
  browser + Node, zero dependencies).
* **Vendored byte-identical copy:** `seal-assurance-kit/kernel/receipt-format.js`
  — same discipline as the kit's existing vendored `kernel.js` /
  `seal-config.js`. Any change lands in seal-check first, then is re-copied.

Frozen exports (signatures are the Day-1 contract):

```js
RECEIPT_SCHEMA_VERSION            // "v1"
RECEIPT_VERSION_KEY               // "seal_receipt"
LEGACY_VERSION_KEYS               // ["seal_live_receipt", "seal_check_receipt"]
VERDICTS                          // ["ALLOW", "BLOCK", "ERROR"]
HOST_AUDIT_VERDICT_MAP            // { allow: "ALLOW", deny: "BLOCK" }
canonicalRequest(tool, args, id=1)      // -> string   (§2 line)
sha256Hex(bytes)                        // -> hex      (pure-JS, browser-safe)
canonicalRequestSha256(tool, args)      // -> hex      (§2)
stableHashParts(parts)                  // -> hex      (§3)
capabilityTarget(tool, parts)           // -> hex      (§3 convention)
capabilityTargetsFromPolicy(cfg, grants) // -> { approvals, opaque, errors } (§3 resolve)
assembleReceiptV1(fields)               // -> object   (§1 fixed key order, byte-stable)
validateReceipt(textOrObj, opts?)       // -> { ok, version, errors, document_checked,
                                        //      record?, receipt_signature_valid? }
                                        //      (§12: v3 adds opts.ed25519Verify + the
                                        //      v3-only flag; §12.6: pass the RECEIVED
                                        //      TEXT — an object cannot be checked
                                        //      against the bytes)
validateReceiptDocument(text, opts?)    // -> same, explicit document entry point (§12.6)
scanReceiptDocument(text)               // -> { ok, errors, topLevel } (§12.6 tokeniser)
DISCRIMINATOR_KEYS                      // the five version-deciding key names (§12.6)
receiptSignaturePreimage(record)        // -> Uint8Array (§12.2 Object B preimage)
postStateHash(operationId, frameSha256) // -> hex      (§12.1 operation-state bind)
verifyReceiptSignature(record, ed25519Verify) // -> { receipt_signature_valid, errors }
```

Both repos ship a vector test (`V1/V2/V2b/V3/V4` above) that fails if the
module and this spec ever disagree. The kit's vendored `kernel.js` is also a
byte-identical copy of seal-check's (pre-existing discipline, re-vendored
with each producer change).

## 10. Day-2 convergence — LANDED (2026-07-04)

1. **DONE** `seal-check/kernel.js buildReceipt` emits v1 via
   `receipt-format.js` (hard-split identity + `asserted_provenance`; grants
   carried as opaque `{target}` entries since seal-check accepts raw
   targets). `app.js` call sites + conformance CLAUSE_MAP updated;
   `SEAL-MEDIATION-PROFILE-L0.md` §4 carries a supersession note.
2. **DONE** `seal-check/receipt.js` validates first, derives the line from
   `(tool, arguments)` (hardcode gone), resolves grants via
   `capabilityTargetsFromPolicy`, replays `now`, checks `emitted_bytes`,
   and reports bypass receipts NOT MEDIATED.
3. **DONE** kit: `gen-receipt.cjs` emits v1 (fixtures regenerated as v1);
   `verify.cjs` accepts v1 + `v0-live`, rejects Schema K, has the bypass
   branch (exit non-zero, prints `NOT MEDIATED`), and derives the hashed
   line from the same call it re-runs, asserting stored-line equality
   first. `fixtures/receipt-bypass.json` exercises the branch in `npm test`.
4. **DONE** cross-tool test: `seal-check/test/fixtures/cross-receipt.json`
   (produced by the shipped seal-check producer, byte-pinned) passes BOTH
   `seal-check/receipt.js` (`test/cross-receipt.test.cjs`) and
   `seal-assurance-kit`'s `seal verify`
   (`fixtures/receipt-crosstool.json`, byte-identical copy, wired into
   `npm test`).
5. seal-live-demo stays as-is (`v0-live` accepted); its own bump to
   `seal_receipt: "v1"` is a separate, later step.

## 11. Authorization-decision schema v2 (pointer)

The v2 delta (`record_type: "seal.authorization-decision"`,
`record_version: 2`; field table, requiredness matrix, derived hashes,
payment class, verifier obligations) is specified upstream in
`seal-host/docs/AUTHORIZATION-DECISION-SCHEMA.md` §11. `receipt-format.js`
§11.x citations refer to that numbering. v2 receipts validate here via
`validateReceipt` (`version: "v2"`).

## 12. Authorization-decision schema v3 (normative for this validator)

**Status: implemented in `receipt-format.js` (2026-08-07), from the accepted
v3 draft (`AUTHORIZATION-DECISION-SCHEMA-V3-DRAFT.md`, seal-host
`probe/record-version-3-spec`).** The native host at `f2c3f89+` emits only
v3. Ruling (option B, 2026-08-07): the four new signed fields are deliberate;
the defect was the missing spec, verifier branch, and fleet propagation. This
section is the seal-check copy of that warrant.

### 12.0 Version discriminator

```
"record_type": "seal.authorization-decision",
"record_version": 3
```

Exact equality per version, one branch each. A verifier MUST NOT range-match
(`record_version >= 2` would silently accept v4/v5 — the exact failure mode
that made v3 invisible). Unknown versions are refused with
`no recognized version discriminator`.

**Dual discriminators are MALFORMED.** A version is claimed through exactly
one of four discriminator key families — six recognized version claims in
total: `seal_receipt: "v1"`, `seal_receipt: "v2"`,
`record_type`+`record_version: 2`, `record_type`+`record_version: 3`,
`seal_live_receipt: "v0"`, and `seal_check_receipt` (legacy Schema K, always
refused). A record presenting keys from more than one family MUST be refused
before classification with `conflicting version discriminators: …` — it is
not any version; it is a document trying to be classified favourably.
Otherwise a signed v3 body with `seal_receipt: "v2"` bolted on classifies as
v2 and the Object B signature check never runs (a downgrade forgery). A
verifier MUST NOT resolve the conflict by priority order — preferring the
highest version present merely converts the downgrade into an upgrade attack.

v3 is **purely additive over v2**: every v2 obligation applies unchanged;
nothing is removed and no v2 field changes meaning.

### 12.1 Field table (delta over v2)

| Field | Type | Required | Semantics |
|---|---|---|---|
| `release_status` | `PENDING`\|`UNKNOWN`\|`RELEASED`\|`NOT_APPLICABLE` | every v3 receipt | Durable release lifecycle. `NOT_APPLICABLE` REQUIRED on non-ALLOW; ALLOW starts `PENDING`, transitions to `UNKNOWN` then `RELEASED` under host recovery (each transition re-signs). |
| `operation_id` | 64 lowercase hex | every v3 receipt | 32 random bytes. On ALLOW, also injected into the forwarded frame as top-level `"operation_id"` and bound by `post_state_hash`. |
| `durability_class` | `asserted_local_fsync`\|`witnessed_external`\|`unknown` | every v3 receipt | Durability claim for how the decision was recorded. The v1 host emitter can only produce `asserted_local_fsync`\|`unknown`; `witnessed_external` is readable, not emittable (type-excluded). Unknown tokens are refused. |
| `signature` | object (§12.2) | every v3 receipt | Ed25519 Object B envelope over the whole record minus this field. **Absent means invalid** — never "optional". |
| `release_valid_until` | integer, epoch ms | ALLOW only | Upper bound for PENDING recovery re-forward. Forbidden on non-ALLOW. |
| `post_state_hash` | 64 lowercase hex | ALLOW only | `sha256` of the compact bytes `{"operation_id":…,"release_frame_sha256":…}` (that member order). Recomputed by the verifier. Forbidden on non-ALLOW. |
| `release_frame` | `{encoding:"base64", length, sha256, base64}` | ALLOW only | Exact frame the host may forward. Verifier recomputes `length`/`sha256` from the decoded bytes and requires the decoded frame's top-level `operation_id` to equal the signed field. Forbidden on non-ALLOW. |

`signature` object shape (exactly these members; extras refused):

```
{
  "domain": "seal.object-b/v1",
  "algorithm": "Ed25519",
  "public_key": "<64 lowercase hex>",
  "key_id": "<64 lowercase hex = sha256(public_key bytes)>",
  "encoding": "base64url-nopad",
  "value": "<base64url-nopad of the 64-byte signature>"
}
```

### 12.2 Signature preimage (exact bytes)

Producer: `seal-host/rust/src/release.rs` (`signature_preimage`,
`ReceiptSigner::sign`/`verify`).

```
preimage = "seal.object-b/v1" || 0x00 || u64_be(len(bytes)) || bytes
bytes    = compact JSON of the record with `signature` removed,
           members in the record's own stored (producer insertion) order
```

The domain constant is 17 bytes **including** the trailing NUL; the wire
`domain` field carries the 16-char name without it.

**The `preserve_order` crux:** serde_json is built with `preserve_order`, so
the covered bytes are in producer insertion order, NOT sorted keys. A
verifier MUST NOT canonicalise or re-order members when rebuilding the
preimage; reordering any two keys changes the preimage and the signature
correctly refuses (measured against a real host receipt, control 6).
Implementation: `receiptSignaturePreimage` in `receipt-format.js`.

Two fail-closed JS re-serialization limits (both refuse, never falsely
accept): JSON.parse fronts integer-like member names, and numbers outside
exact-double round-trip (≥ 2^53 or non-shortest float spellings) lose their
source bytes. Neither occurs in host output today.

**Coverage:** every top-level field present at sign time except `signature`
itself — the four v3 fields, the ALLOW companions, and the entire v2 body.
Not covered / not claimed: kernel correctness (that is replay), caller
identity, config authority, approval keys.

### 12.3 Verifier obligations (delta over v2)

`validateReceipt(r, { ed25519Verify })` enforces, in addition to all v2
obligations:

1. Enum/hex/shape checks on the four always-present fields.
2. ALLOW: require the three companions; recompute `release_frame.length` and
   `.sha256`; require decoded-frame `operation_id` == signed `operation_id`;
   recompute `post_state_hash`.
3. Non-ALLOW: require `release_status: "NOT_APPLICABLE"`; forbid all three
   companions.
4. Rebuild the §12.2 preimage and verify Ed25519 under the embedded
   `public_key`; require `key_id == sha256(public_key bytes)`; refuse
   unknown `domain`/`algorithm`/`encoding`.
5. **Fail closed on missing crypto:** the module is dependency-free, so the
   Ed25519 primitive is injected (`opts.ed25519Verify(message, signature,
   publicKey) -> boolean`; e.g. tweetnacl's `nacl.sign.detached.verify`).
   Without it a v3 receipt FAILS with an explicit `UNVERIFIED` error.
   Signature verification is never skipped, including when `signature` is
   absent.

### 12.4 Flag naming and the two other `signature`s

The result field is **`receipt_signature_valid`** (v3 results only). It is
deliberately NOT `signature_valid`: downstream verifiers already use
`signature_valid` for the **`signed_config`** Ed25519 envelope, a different
object under a different key. The third collision is v1's optional live-demo
HMAC field also named `signature` — a different shape that can never reach
the v3 branch (disjoint discriminators; a record carrying both families is
refused as malformed under the §12.0 dual-discriminator rule).

**Trust caveat:** `receipt_signature_valid: true` binds the record to the
*embedded* public key. Binding that key to a deployment requires an
out-of-band pin (`key_id`/`public_key`); no fleet-published trust root
exists today. Do not report an embedded-key pass as installation
authentication.

### 12.5 Vectors and controls

`test/receipt-format-v3.test.cjs` pins the preimage byte layout, validates a
real host v3 BLOCK receipt (`test/fixtures/host-v3-block.receipt.json`) and
a real host v2 receipt (no regression), exercises the ALLOW release-authority
path with a producer-mirroring minted vector, and runs the negative
controls: flipped `signature.value`, flipped covered field, removed
`signature`, reordered keys, unknown `record_version`, unknown enum tokens,
frame/bind mismatches. Each control is REFUSED distinctly.

### 12.6 The received DOCUMENT — a CONTRACT CHANGE for callers

Everything above §12.6 validates the object `JSON.parse` produced. That object
is not the receipt. The receipt is the byte string a producer signed, and
`JSON.parse` is lossy about it:

* a repeated member collapses to its **last** occurrence;
* `3`, `3.0`, `3e0` fold to the same double;
* `"record_version"` and `"record_version"` become the same key.

The exhibit that forced this section (frisk A9): a **real host v3 receipt**
whose text carries both `"record_version": 3` and `"record_version": 2`
parses to a v2 object. It classifies as v2, so the Object B signature is never
verified, and validation returns `ok: true, version: "v2", errors: []` — with
the signature stripped, the verdict forged to `ALLOW`, and even under an
always-false Ed25519 primitive. The §12.0 multi-family conflict rule cannot
see it: after the parse there is genuinely one family with one value. Nothing
is wrong with the object. The lie is in the bytes.

**The contract.** `validateReceipt` now takes EITHER form, and the choice is
load-bearing:

```js
validateReceipt(rawText, { ed25519Verify })  // REQUIRED for anything received
  // -> { ok, version, errors, document_checked: true, record, … }
validateReceipt(object,  { ed25519Verify })  // minted-in-process records only
  // -> { ok, version, errors, document_checked: false, … }
```

* **Anything that arrived** — a URL fragment, a file, a peer, a queue — MUST be
  passed as the **raw text**. The document checks are impossible otherwise.
  `record` carries the parsed object so the caller need not parse twice.
* **The object form stays supported** for records this process minted, where no
  received bytes exist. It reports `document_checked: false`, and that flag is
  not decoration: `ok: true` with `document_checked: false` says *this object
  is well formed*, never *the bytes we received say this*. A consumer that
  treats the two as the same thing has the A9 bug.
* `verifyReceipt(input, …)` (receipt.js) takes the same either/or, and there
  the distinction is carried by the RESULT TYPE, not by a flag a consumer may
  skip: an object input can never produce `outcome: "authorised"`,
  `"authorised-unparseable"` or `"unpinned"`, never `verificationCore: true`,
  never `allGood: true`. Its ceiling is the distinct outcome
  **`unverified-document`** (every local check passed; no received bytes were
  examined) — the same discipline as §11.1's `authorised-unparseable`: a
  smaller verification scope is its own named state, not a pass. A consumer
  that keys only on `outcome` — as `test/verify-file.cjs` does — therefore
  cannot mistake an object-path result for a verified wire receipt.
  `decodeReceiptDocument()` returns the deep
  link's raw text; `decodeReceiptParam()` (parsed) remains for callers that
  only want to *read* fields and must not be used as verification input.
* Callers updated in this repo: `app.js` (deep link → text), `test/verify-file.cjs`
  (file bytes → text). Both had the bytes in hand already.

**What the document check does.** Before parsing, the text is walked by a JSON
**tokeniser** (`scanReceiptDocument`) — not a regex, because a string that
looks like `"record_version"` may legitimately appear inside a *value*, and
counting textual occurrences would refuse honest receipts. The scan reports
only genuine **top-level member names**, with `\u` escapes decoded, and the
document is refused as MALFORMED when:

1. any of the five discriminator names (`seal_receipt`, `record_type`,
   `record_version`, `seal_live_receipt`, `seal_check_receipt`) occurs more
   than once at the top level — the A9 class, including the case where the
   second occurrence is spelled with escapes;
2. any other top-level member occurs more than once (a duplicated member is
   ambiguous about what was signed; no fixture or producer in this repo emits
   one);
3. a discriminator name is written with a `\u` escape at all;
4. `record_version` is written as anything but a bare integer literal
   (`3.0`, `3e0`, `2.0` are refused — the host producer emits `3`);
5. the document begins with a BOM, is not well-formed JSON, or carries
   trailing content. A BOM is **not** stripped: silently repairing input is how
   a verifier ends up judging bytes nobody sent.

Nothing is canonicalised or re-serialised: the same untouched bytes go to
`JSON.parse`, so §12.2's `preserve_order` preimage is unaffected.

**Not covered, deliberately.** Duplicate or escaped members *nested* inside
values are not refused (on v3 they break the signature; v2 carries no Object B
envelope to break). Key-order normalisation by an intermediary cannot be
detected after the fact — it breaks the v3 signature and fails closed. Numeric
spellings of fields other than `record_version` are likewise left to the
signature. And a caller that hands over an object sees none of this by
construction — hence `document_checked`.

`test/receipt-document.test.cjs` carries A9 (both oracles, forged and
unforged), one construction per class above, the lazy-fix traps (a
discriminator name quoted inside a value; a nested member with that name), and
the real fixtures — host v3, host v2, fleet v2, unparseable-request — all
still validating through the document path.
