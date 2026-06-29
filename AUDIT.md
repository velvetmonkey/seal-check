# IP audit — seal-check v0

seal-check ships only public v1 artifacts. This file records the audit that gates
that claim. Re-run the commands before any publish.

## Pinned kernel binary

```
sha256(wasm/seal.wasm) = 1cc765c7de2cead88eda2e8e5f5af5a5e070f35a767916e754b873733562c70a
size = 3,462,118 bytes
```

The page recomputes this in-browser on load (SubtleCrypto) and refuses to emit
receipts if it does not match.

## What was audited (2026-06-29)

The four reused artifacts were copied from `seal-demo/public/` and scanned for any
leak of the **private** repos (`seal-host`, `mcp-seal-dev`) — paths, commit SHAs,
hostnames, author identity, or private source structure.

| Artifact | Source | Result |
|---|---|---|
| `wasm/seal.wasm` | seal-demo (compiled black-box) | no path / repo / commit / author leak |
| `wasm/seal.js` | seal-demo (emscripten glue) | no private markers |
| `seal-wasm.js` | seal-demo (Apache-2.0 adapter) | clean (kept as upstream reference) |
| `seal-config.js` | seal-demo (Apache-2.0 config) | 2 stale `seal_host_step` comments → reworded to `seal_decide` |

### Strings embedded in the wasm
The binary exposes only:
- **Public kernel type names** — `SealCore.Decision.{allow,block}`,
  `SealCore.Event.*`, `SealV2.AST.*`. `SealCore`/`SealV2` are names from the
  **published** `mcp-seal` repo; the AST names are generic JSON constructors.
- **Lean compiler runtime strings** — e.g. `runElab`, `showTermElab`, `delta`,
  `zetaDelta`, and a Lean-internal 40-hex constant (`7e01a1bf…`, confirmed **not**
  a git object in any seal repo, public or private).

No `seal-host`, `mcp-seal-dev`, `wasm-spike`, `monkey-01`, `/home/…`, `Kernels/`,
`Host/`, `Ffi`, or `G1`–`G7` strings appear. The compiled artifact is the
README-designated public "black-box evaluator."

### Note on symbol stripping
Stripping the public Lean type names from the wasm would require a recompile of
the kernel (out of scope, and forbidden for this build — we reuse the artifact as
is). Since nothing **private** is exposed, no scrub is required. A future hardening
pass can rebuild the wasm with symbol stripping in the private build pipeline.

## Re-run the audit

```sh
sha256sum wasm/seal.wasm   # must equal the pinned value above

# no private markers in any shipped file:
grep -rEi 'seal-host|mcp-seal-dev|wasm-spike|monkey-01|/home/|record.?core' \
  --exclude-dir=.git . ; echo "exit=$?  (1 = clean / no matches)"

# no private markers in the binary:
strings -n 5 wasm/seal.wasm | grep -Ei 'seal-host|mcp-seal-dev|wasm-spike|/home/|/Users/'
```

## Publish gate
This repo is built **private**. Public release of the compiled kernel is a separate,
owner-authorized step. Do not enable a public deploy without re-running this audit.
