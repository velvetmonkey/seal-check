# seal-check

**Paste a receipt. A tampered one fails in your browser — the real kernel re-derives the verdict live. No server, no account, no faith required.**

Drop a tool-call or receipt JSON (or open a deep link). seal-check re-runs the proven decision procedure over the exact bytes. Genuine = PASS. Tampered = FAIL, right in front of you.

One command serves the page. Click the tamper example and watch it fail. That's the product.

![Runtime](https://img.shields.io/badge/runtime-WebAssembly-654ff0)
![Verifier](https://img.shields.io/badge/verifier-browser-informational)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

<!-- truthbox:begin -->
> **Runtime profile: `compatible`.** Strict `canonical-l0` is proved and modelled, not the deployed route yet.
> **Claim:** policy-covered request-effects recognised by the compatible MCP boundary require a matching live human approval and an allowing Lean kernel verdict; seam failures block; every decision emits replayable evidence.
> **Non-claim:** the deployed host is not proved end to end, and canonical parser rejection is not currently the runtime gate. Host `ApprovalRecord` tokens are a separate signed channel from the v2 canonical approval tuple.
<!-- truthbox:end -->
> Map: [EVALUATOR-START.md](https://github.com/velvetmonkey/seal/blob/main/EVALUATOR-START.md) · profile detail: [PROFILE.md](https://github.com/velvetmonkey/seal-host/blob/main/PROFILE.md) — both in private repos; the links resolve only for authorised evaluators.

**Luxury 1-minute showcase**

```bash
python3 -m http.server 8000   # then visit http://localhost:8000
```

Open the page (http, not file://). Paste a receipt or click the built-in "Verify a receipt" / tamper examples. You will see the verdict recomputed live in WASM and a tampered receipt fail visibly.

The page bundles the audited wasm, re-runs the kernel, and shows the result. Nothing leaves the browser.

<!-- TODO(asset, shot #4): real screenshot — the verdict row + decision-receipt panel
     (Allow/Block + the JSON receipt) from the live page. It IS the product; capture it,
     do not illustrate it. -->
<!-- TODO(asset, shot #3, PROMO-GRADE): real screen-capture GIF — "Verify a TAMPERED
     receipt" failing in front of you (the money shot from index.html §1b). -->


## What happens when someone hands you a decision receipt

Receipts arrive as deep links: open the page with `#receipt=<base64url of the receipt JSON>` (that is how seal-live-demo hands you one) and it is re-verified in your browser — or use the "Verify a receipt" buttons on the page to watch a genuine receipt pass and a tampered one fail. The page hashes its bundled wasm, checks the pinned identity, re-runs the same kernel, and compares the emitted bytes. It also mirrors the target commitment in JavaScript: code-point-count netstrings, UTF-8 bytes, SHA-256, lowercase hex.

Nothing you paste leaves the page. The page verifies a decision artifact; it does not certify that your whole deployment is correctly wired through Seal.

## For evaluators and auditors

Seal's proof story is intentionally narrow. The Lean theorems cover the mediation kernel and selected model properties. The binaries and browser artifacts are connected to that proof by reproducible conformance tests, not by a theorem about every compiled instruction. For this page's wasm specifically, a differential harness drives identical inputs through the deployed `seal.wasm` and the proven model: currently 13/13 mediation-corpus adversarial cases agree with 0 disagreements — evidence, not a theorem ([assurance statement](docs/SEAL-ASSURANCE-STATEMENT.md)).

Start with the family [claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md) (one table: proven / tested / assumed / not claimed) and [What Seal is NOT](https://github.com/velvetmonkey/seal-assurance-kit/blob/main/docs/WHAT-SEAL-IS-NOT.md), then [docs/PROOF-REFERENCE.md](docs/PROOF-REFERENCE.md) for theorem names and file locations, [docs/CONFORMANCE.md](docs/CONFORMANCE.md) for the byte-identity claim, and [docs/TCB.md](docs/TCB.md) for what remains trusted.

Mandatory non-claims (canonical copy: [docs/LIMITATIONS.md](docs/LIMITATIONS.md)):

<!-- claims:begin -->
- Seal proves properties of the mediation KERNEL, not of the whole deployed system.
- Seal does NOT prove SHA-256 collision resistance in Lean; it is a named, scoped cryptographic assumption (A-CR).
- The deployed Rust / wasm / JS are NOT proven bug-free; they are tied to the proof by byte-exact conformance testing over a corpus, not for every possible input.
- Seal guarantees AUTHORIZATION match, not INTENT match: if a human approves a malicious-but-valid request, Seal will execute it.
- Seal does NOT prevent compromise of hosts, browsers, build systems, keys, operators, or downstream tools.
- Seal's audit chain is tamper-EVIDENT, not tamper-IMPOSSIBLE.
- Seal does NOT make the AI smarter or prevent hallucinations; it stops an unapproved effect.
- Axiom footprint {propext, Classical.choice, Quot.sound} is the minimal classical fragment; no extra axioms.
<!-- claims:end -->

## Verify in five minutes

Open the page (the wasm fetch needs http, not file://):

```sh
python3 -m http.server 8000   # then visit http://localhost:8000
```

Reproduce off-browser — these are standalone, need no server, and run the same
shipped wasm under Node:

```sh
node test/receipt-format.test.cjs
node test/receipt-harness.cjs
node test/cross-receipt.test.cjs
node test/receipt-verify.test.cjs   # negative paths: tampered receipts must FAIL
```

## The Seal family

_All Seal-family repositories are currently private; these links resolve only for authorised evaluators._

- [seal](https://github.com/velvetmonkey/seal): the private umbrella story, product map, and evaluator path.
- [mcp-seal-dev](https://github.com/velvetmonkey/mcp-seal-dev): The rulebook, proven.
- [seal-host](https://github.com/velvetmonkey/seal-host): The guard at the door.
- [seal-check](https://github.com/velvetmonkey/seal-check): Don't trust. Verify.
- [seal-live-demo](https://github.com/velvetmonkey/seal-live-demo): Watch it work.
- [seal-assurance-kit](https://github.com/velvetmonkey/seal-assurance-kit): Check your own boundary.
- [witness-check](https://github.com/velvetmonkey/witness-check): The sufficiency analyzer. (proprietary)
- [seal-verify-action](https://github.com/velvetmonkey/seal-verify-action): Gate receipts in CI.

## Documentation

- [What Seal is NOT](https://github.com/velvetmonkey/seal-assurance-kit/blob/main/docs/WHAT-SEAL-IS-NOT.md) — read this first (private kit repo)
- [Family claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md) · [family architecture map](https://github.com/velvetmonkey/seal/blob/main/docs/ARCHITECTURE.md) (private umbrella)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Assumptions](docs/ASSUMPTIONS.md)
- [Proof reference](docs/PROOF-REFERENCE.md)
- [Conformance](docs/CONFORMANCE.md)
- [Trusted computing base](docs/TCB.md)
- [Glossary](docs/GLOSSARY.md)
- [Limitations](docs/LIMITATIONS.md)
- [Security policy](SECURITY.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
