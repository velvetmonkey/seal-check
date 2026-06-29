<!-- SPDX-License-Identifier: Apache-2.0 -->
# seal-check

**Is your MCP boundary _actually_ mediated?** Paste an MCP tool-call, get a
deterministic **Allow / Block** verdict and a reproducible **receipt** from the
verified **seal** kernel — running entirely in your browser.

seal-check is the L1 adoption wedge for [seal](https://github.com/velvetmonkey/mcp-seal),
a Lean-4-verified MCP mediation gate. It is a single static page: **no backend, no
accounts, no telemetry, nothing you paste leaves the page.**

> **Status: private/local build.** The compiled kernel has not been published. Run
> it locally (below). Public deployment is a separate, owner-authorized step.

## What it does

1. **Check a call** — paste a JSON-RPC `tools/call` (or a simple
   `{ "tool", "args", "approvals" }`), run it against a standard multi-kernel
   policy, and get `ALLOW` / `BLOCK` plus a **decision receipt**: the verbatim
   emitted bytes, the per-gate parse witness, and the pinned kernel `sha256`. The
   receipt is downloadable and **byte-identical for the same input, every reload**.
2. **Replay known attacks** — five named bypass / parser-differential /
   stale-capability traces that the live kernel deterministically **blocks**
   (destructive SQL, self-approval, missing-quorum payment, non-convergent store
   write, stale-capability-after-revoke).
3. **Badge + claim discipline** — a copyable "seal-checked boundary" badge carrying
   the kernel's short sha, and a permanent **What this proves / What it does NOT
   prove** panel.

## Run it locally

WASM needs an HTTP origin (`file://` is blocked) and a secure context for the
in-browser sha256 — `localhost` qualifies.

```sh
cd seal-check
python3 -m http.server 8000
# open http://localhost:8000
```

## The receipt

Two strictly-separate, labelled blocks — binary identity vs proof hygiene. The
hash is **never** presented as proving the axioms.

- `kernel_identity.wasm_sha256` — the binary actually executed, **hashed in your
  browser** and compared to a pinned constant. This is the **only** thing verified
  in-browser.
- `asserted_provenance` — the Lean toolchain (`leanprover/lean4:v4.28.0`) and axiom
  footprint (`propext`, `Classical.choice`, `Quot.sound`) the public proofs
  **assert**. Flagged `verified_in_browser: false`. Not part of the hash.
- `emitted_bytes` — the verbatim `seal_decide` output.
- `witness.certs` — the per-gate seals (FNV-1a 64-bit cert hashes).

## What this proves — and what it does not

**Proves:** for the exact call you supplied, this is the deterministic Allow/Block
decision produced by the seal kernel whose binary `sha256` is shown, executed in
your browser, whose decision logic is the subject of public Lean 4 proofs (modulo
their stated assumptions and axioms). Same input → byte-identical receipt.

**Does NOT prove:** it does not certify your whole MCP server, transport, tool
implementations, or that your deployment routes calls through the gate. The sha256
verifies *which binary ran* — not the axioms or the proofs. No third party
certifies anything here; **ARIA certifies nothing** — no endorsement, outcome, or
affiliation is claimed or implied.

## Architecture

Vanilla JS, no build step.

| File | Role |
|---|---|
| `wasm/seal.{js,wasm}` | compiled black-box kernel (emscripten; symbols `seal_init`, `seal_decide`) |
| `seal-config.js` | input/output shaping + scenario configs (reused, public) |
| `seal-wasm.js` | upstream adapter, kept for provenance reference |
| `kernel.js` | **the only new logic**: raw-byte capture, sha self-verify, receipt builder |
| `corpus.js` | the five named attack traces (data only) |
| `app.js`, `index.html`, `style.css` | UI |

IP boundary and the binary audit are documented in [AUDIT.md](AUDIT.md). seal-check
bundles only public artifacts; it never references the private `seal-host` or
`mcp-seal-dev` repos.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
