# seal-check

A static browser verifier for Seal decisions and receipts. **Role:** Don't trust. Verify.

![Runtime](https://img.shields.io/badge/runtime-WebAssembly-654ff0)
![Verifier](https://img.shields.io/badge/verifier-browser-informational)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

> **Runtime profile: `compatible`.** Strict `canonical-l0` is proved and modelled, not the deployed route yet.
> **Claim:** policy-covered request-effects recognised by the compatible MCP boundary require a matching live human approval and an allowing Lean kernel verdict; seam failures block; every decision emits replayable evidence.
> **Non-claim:** the deployed host is not proved end to end, and canonical parser rejection is not currently the runtime gate. Host `ApprovalRecord` tokens are a separate signed channel from the v2 canonical approval tuple, and the live demo still emits legacy v0 receipts.
> Map: [EVALUATOR-START.md](https://github.com/velvetmonkey/seal/blob/main/EVALUATOR-START.md) · profile detail: [PROFILE.md](https://github.com/velvetmonkey/seal-host/blob/main/PROFILE.md).

**Seal is a proven checkpoint for AI agents.** When an AI agent tries to use a real tool over MCP (send money, delete a record, call an external service), Seal stands in the way and asks one question: did a human explicitly approve *this exact request*? No matching approval, no action. Every decision is written into a tamper-evident record you can check yourself. What makes Seal different from other guardrails: the core mediation rules aren't just tested, they're machine-checked theorems in Lean 4. The same decision logic then runs byte-for-byte in the Rust host you deploy, in the browser, and in the checker, each verified against that one proven rulebook.

That is the product line in one sentence: prove the rulebook, then check every body that runs it. Seal is built around MCP because MCP is where agent intent becomes an external effect. The proof says what the kernel must do; the conformance tests show that the Rust, wasm, and JavaScript artifacts used by the product family emit the same decisions and records over the shared corpus.

## What happens when someone hands you a decision receipt

Receipts arrive as deep links: open the page with `#receipt=<base64url of the receipt JSON>` (that is how seal-live-demo hands you one) and it is re-verified in your browser — or use the "Verify a receipt" buttons on the page to watch a genuine receipt pass and a tampered one fail. The page hashes its bundled wasm, checks the pinned identity, re-runs the same kernel, and compares the emitted bytes. It also mirrors the target commitment in JavaScript: code-point-count netstrings, UTF-8 bytes, SHA-256, lowercase hex.

Nothing you paste leaves the page. The page verifies a decision artifact; it does not certify that your whole deployment is correctly wired through Seal.

## For evaluators and auditors

Seal's proof story is intentionally narrow. The Lean theorems cover the mediation kernel and selected model properties. The binaries and browser artifacts are connected to that proof by reproducible conformance tests, not by a theorem about every compiled instruction.

Start with [docs/PROOF-REFERENCE.md](docs/PROOF-REFERENCE.md) for theorem names and file locations, [docs/CONFORMANCE.md](docs/CONFORMANCE.md) for the byte-identity claim, and [docs/TCB.md](docs/TCB.md) for what remains trusted.

Mandatory non-claims:

- Seal proves properties of the mediation KERNEL, not of the whole deployed system.
- Seal does NOT prove SHA-256 collision resistance in Lean; it is a named, scoped cryptographic assumption (A-CR).
- The deployed Rust / wasm / JS are NOT proven bug-free; they are tied to the proof by byte-exact conformance testing over a corpus, not for every possible input.
- Seal guarantees AUTHORIZATION match, not INTENT match: if a human approves a malicious-but-valid request, Seal will execute it.
- Seal does NOT prevent compromise of hosts, browsers, build systems, keys, operators, or downstream tools.
- Seal's audit chain is tamper-EVIDENT, not tamper-IMPOSSIBLE.
- Seal does NOT make the AI smarter or prevent hallucinations; it stops an unapproved effect.
- Axiom footprint {propext, Classical.choice, Quot.sound} is the minimal classical fragment; no extra axioms.

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

## Documentation

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
