<!-- SPDX-License-Identifier: Apache-2.0 -->
# seal — Assurance statement

| | |
|---|---|
| **Status** | `draft` |
| **Date** | 2026-07-02 |
| **License** | Apache-2.0 (see `../LICENSE`) |

This is the public statement of what seal proves, what it trusts, and where the
evidence for each lives. It is the companion to
`SEAL-MEDIATION-PROFILE-L0.md` (the boundary contract) and to the `seal-check`
widget (the executable demonstration). It deliberately states the proof **and**
the trusted base with equal weight; that is the point of the document.

---

## 0. What seal does NOT claim

seal is a mediation kernel with a machine-checked non-bypass property. It is
**not** a proof of agent safety, and it does not certify a whole MCP server,
its transport, or its tool implementations.

The claim seal makes is exactly this, and nothing wider:

> **Policy-covered, unapproved effects cannot execute through the mediated MCP
> boundary, as modelled.**

Every qualifier is load-bearing:

- **policy-covered** — calls the trusted policy identifies as guarded and calls
  it explicitly allows are gated. A call the policy does not cover is out of scope, not "safe".
- **unapproved** — an effect with a valid, fresh, target-bound approval is
  *admitted*; seal blocks the *unapproved*, not the approved.
- **through the mediated MCP boundary** — effects that never emit a
  `tools/call` through the gate (a side channel, an out-of-band write, a
  lenient child that executes what strict JSON rejects) are outside the
  boundary by construction.
- **as modelled** — the proof is over the formal model of parse / validate /
  decide. The model's fidelity to the deployed binary rests on the named
  trusted set (§2), not on further proof.

Specifically, seal does **NOT** claim:

- that "agent safety is solved" or that a seal-mediated agent is safe;
- that "nothing leaks" — **responses are relayed unmediated by design**
  (requests are gated, response egress is not);
- **that the deployed wasm provably equals the model** — the equivalence is a
  *trusted compile* (verified-language codegen + the wasm toolchain) plus
  *differential testing*, **not** a proof;
- that a deployment actually routes its calls through the gate (an integration
  property of the operator, not a theorem);
- any third-party endorsement, outcome, or affiliation. In particular no ARIA
  endorsement, outcome, or status is claimed or implied, regardless of any
  process state.

**This posture is the precedent, not a weakness.** seL4 ships a machine-checked
functional-correctness proof *together with* an explicit list of assumptions it
does not discharge (the C compiler, the assembly, the hardware model).
CompCert ships a proved-correct C compiler whose guarantee is stated *relative
to* its formal semantics and its trusted parser / assembler. Both are landmark
results precisely because they state the proof **and** the trusted base with
equal rigor. seal follows that discipline: a narrow proven core, an explicitly
named TCB, and claim discipline that refuses to let the proof's reputation
extend past what was proven.

---

## 1. What is proven (machine-checked)

The decision logic is a Lean 4 model of a three-stage pipeline —
`parse : RawBytes → Option AST`, `validate : AST → ApprovalState → Option
witness`, `decide : RawBytes → ApprovalState → Decision`. Over that model, three
theorems are discharged with **zero `sorry`** and no `native_decide`:

| Theorem | Plain statement |
|---|---|
| **`non_bypass`** | An `Allow` implies the request parsed to an AST **and** a validated capability witness exists whose canonical serialization is the emitted bytes. No admission without a parsed request and a validated capability. |
| **`default_deny`** | If the bytes do not parse, or parse but fail validation, the decision is `Block`. Ambiguity resolves to refusal. |
| **`decide_emit_unique`** | An `Allow`'s output bytes are uniquely determined by the validated witness — a single, unambiguous emit path. |

**Axiom footprint** of every discharged theorem:
`[propext, Classical.choice, Quot.sound]` — the standard classical-logic base,
nothing exotic, no `sorryAx`. A continuous-integration axiom check gates this on
every commit to the proof repository.

The reference host bridge that sits at the tool-call boundary adds four
properties that are **enforced-by-construction** (the code cannot be made to
violate them without a type error) and pinned by tests: an admit action is
constructible only from a real kernel verdict; every FFI error resolves to
refuse (fail-closed); admitted bytes are forwarded verbatim; and a kernel panic
terminates the process rather than returning a default that could admit.

---

## 2. What is trusted (named, not proven)

The proof is exact within its model. Everything below is trusted — named here so
a reviewer can weigh it, in the seL4 / CompCert tradition:

- **The verified-language compiler, runtime, and C code generator** that compile
  and host the proven decision function.
- **The WebAssembly toolchain** that produces the deployed `seal.wasm` from the
  generated C.
- **The wasm-equals-model identity** — that the shipped binary computes the same
  function as the proven model. This is the *trusted compile* above plus
  *differential testing* (§3), **not** a theorem. The in-browser SHA-256 proves
  *which binary ran*; it never proves *that the binary matches the model*.
- **The C ABI marshalling shim** and the standard-library string helpers it
  re-exports.
- **The operating-system process model and file permissions** — pipes, process
  spawn, and write access to the trusted policy, approval, and evidence files.
  Whoever can write the approval file is, in effect, an approver.
- **The wall clock and the freshness state** (nonce-replay set, TTL, future-skew
  rejection) the model assumes as given inputs.
- **`serde_json` and `ed25519-dalek`** on the host approval-evidence path.
  In `seal-host`, the NDJSON signed-token provider signs exact
  `ApprovalRecord` JSON payload bytes; the SealV2 canonical signed-message
  token in `mcp-seal-dev` signs `(target, session, issuedAt, expiry, nonce)`.
  Their failure direction is to drop the record — i.e. to **deny**.
- **Response egress is not mediated, by design.** Requests are gated; the bytes
  a server sends back to the client are relayed unmediated. Do not read seal's
  guarantee as "nothing leaks".
- **The operator's command line**, which names the guarded server, and the
  assumption that the guarded server parses its protocol strictly.

---

## 3. Where the evidence lives

Evidence is of two kinds, and the distinction is deliberate:

**Publicly re-runnable by any third party.**
- The three theorems and their axiom footprint — clone the public Lean proof
  repository and run `lake build` plus the axiom check. The proofs either
  check or they do not; this needs no trust in us.
- Binary identity — load the `seal-check` widget over an `http(s)` or
  `localhost` origin and let it recompute the kernel SHA-256 in your browser,
  comparing against the pinned constant. This establishes *which binary ran*.

**Attested (in the private integration repository), available to reviewers.**
- The host-bridge properties of §1 are pinned by a fail-closed FFI probe, a
  routing-agreement corpus (including the full obfuscation-disguise set), and a
  full-path conformance oracle that drives the real binary end-to-end.
- A **wasm-vs-model differential harness** drives identical inputs through the
  deployed `seal.wasm` and the proven model and checks for identical verdicts.
  This is *risk-reducing evidence* for the wasm-equals-model identity (§2), not
  a proof of it. Status: green (2026-07-02), 13/13 mediation-corpus adversarial
  cases (delete-command disguises, structural JSON manglings, `\u`-escaped forms)
  agree and Block across the emscripten wasm and the natively-compiled model,
  with 0 disagreements. Scope is the mediation corpus, not exhaustive over all
  inputs. The harness lives in the private integration repository; the result is
  attested and available to reviewers on request.

---

## 4. Evidence map (public subset)

For each publicly re-runnable claim, the artefact that backs it:

| Claim | Backed by | How to re-run |
|---|---|---|
| No admission without a parsed, validated capability | theorem `non_bypass`, `SealV2/DecideTheorems.lean` | `lake build` in the public proof repo |
| Unparseable / unvalidated ⇒ Block | theorem `default_deny`, `SealV2/DecideTheorems.lean` | `lake build` |
| Admitted bytes uniquely determined; single emit path | theorem `decide_emit_unique`, `SealV2/DecideTheorems.lean` | `lake build` |
| Axiom footprint `[propext, Classical.choice, Quot.sound]`, zero sorry | CI axiom check in the public proof repo | `lake exe axiom_check` |
| Which binary produced a decision (identity, not equivalence) | in-browser SHA-256 self-verify, pinned constant | load the widget, read `kernel_identity` |
| Determinism: same input ⇒ byte-identical receipt | receipt harness | `node test/receipt-harness.cjs` |

Host-bridge and wasm-vs-model evidence is attested and available to reviewers on
request; it is not part of this public artefact. The wasm-vs-model differential
is green as of 2026-07-02 (13/13 mediation corpus, 0 disagreements); it remains
*risk-reducing evidence* for the trusted-compile identity, never a proof of it.
