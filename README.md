<!-- SPDX-License-Identifier: Apache-2.0 -->
# seal-check `v0`

**Is your MCP boundary _actually_ mediated?** Paste an MCP tool-call, get a
deterministic **Allow / Block** verdict and a reproducible **receipt** from the
verified **seal** kernel — running entirely in your browser.

seal-check is the L0 adoption wedge for [seal](https://github.com/velvetmonkey/mcp-seal),
a Lean-4-verified MCP mediation gate. It is a single static page:
**no backend, no accounts, no telemetry — nothing you paste leaves the page.**

> **Status: private / local build.** The compiled kernel has not been published. Run
> it locally (below). The public flip is a separate, explicitly-authorised step — see
> [AUDIT.md](AUDIT.md).

## Run it

WASM needs an HTTP origin (`file://` is blocked). A secure context (`https`,
`localhost`, `127.0.0.1`) uses native SubtleCrypto for the self-verify; any other
http origin (e.g. a LAN hostname) falls back to a bundled pure-JS SHA-256.

```sh
cd ~/src/seal-check
python3 -m http.server 8000
# open http://localhost:8000   (or http://<host>:8000 on the box)
```

## What the page does

1. **Check a call** — paste a JSON-RPC `tools/call` (or a simple
   `{ "tool", "args", "approvals" }`); it runs against a standard multi-kernel policy
   and shows `ALLOW` / `BLOCK`, the deny gate, the per-gate witness, and a **decision
   receipt** (verbatim emitted bytes + parse witness + pinned kernel `sha256`). The
   receipt downloads and is **byte-identical for the same input, every reload**.
2. **Replay known attacks** — five named bypass / parser-differential /
   stale-capability traces that the live kernel deterministically **blocks**
   (destructive SQL, self-approval, missing-quorum payment, non-convergent store
   write, stale-capability-after-revoke). "Replay all" → `5/5 blocked`.
3. **Badge** — a copyable "seal-checked boundary" badge (SVG or Markdown) carrying the
   kernel's short sha.
4. **Conformance map** — maps each live receipt field to the clause it satisfies in
   [SEAL-MEDIATION-PROFILE-L0](docs/SEAL-MEDIATION-PROFILE-L0.md).

## What this proves — and what it does not

**Proves:** for the exact call you supplied, this is the deterministic Allow/Block
decision produced by the seal kernel whose binary `sha256` is shown, executed in your
browser, whose decision logic is the subject of public Lean 4 proofs (modulo their
stated assumptions and axioms). Same input → byte-identical receipt.

**Does NOT prove:** it does not certify your whole MCP server, transport, tool
implementations, or that your deployment routes calls through the gate. The sha256
verifies *which binary ran* — not the axioms or the proofs. No third party certifies
anything here; **ARIA certifies nothing** — no endorsement, outcome, or affiliation is
claimed or implied.

**Profile:** seal's deployed host mediates under the `compatible` profile, not strict
canonical-l0 (see seal-host CLAIMS.md); the canonical AST is audit input to the kernels,
not the mediation gate.

## Kernel identity

| | |
|---|---|
| **wasm sha256** | `ebd17c14668176612c49f6e2940b23df82a2c1a7cdef6759f0d6276ae997e9d0` — **self-verified in browser** against a pinned constant |
| **lean toolchain** | `leanprover/lean4:v4.28.0` — *asserted provenance, not verified here* |
| **axiom footprint** | `propext` · `Classical.choice` · `Quot.sound` — *asserted, not verified here* |

The sha256 is the only thing verified at decision time. Toolchain and axioms are what
the public proofs **assert** about the source; they are disclosed as a separate,
clearly-labelled block and are never blended into the hash. Full rules:
[SEAL-MEDIATION-PROFILE-L0 §6](docs/SEAL-MEDIATION-PROFILE-L0.md).

## Architecture

Vanilla JS, no build step. The runtime is the static page only.

| File | Role |
|---|---|
| `wasm/seal.{js,wasm}` | compiled black-box kernel (emscripten; symbols `seal_init`, `seal_decide`) |
| `seal-config.js` | input/output shaping + scenario configs (reused, public) |
| `seal-wasm.js` | upstream adapter, kept for provenance reference |
| `kernel.js` | raw-byte capture, in-browser sha256 self-verify (+ JS fallback), receipt builder |
| `corpus.js` | the five named attack traces (data only) |
| `app.js`, `index.html`, `style.css` | UI |
| `docs/SEAL-MEDIATION-PROFILE-L0.md` | the L0 conformance profile |
| `test/receipt-harness.cjs` | **TEST-ONLY** — reproduces receipts under Node; not part of the runtime |

IP boundary and the binary audit / publish gate are documented in [AUDIT.md](AUDIT.md).
seal-check bundles only public artifacts; it never references the private seal kernel
development repos.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
