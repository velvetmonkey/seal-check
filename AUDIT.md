# IP audit & publish gate — seal-check v0

seal-check ships only public v1 artifacts. This file is the **publish gate**: the
checklist below MUST pass before any public flip, and the flip itself is a separate,
explicitly-authorised manual procedure (§Flip). Re-run the commands before publishing.

**Current status: PASS (private). NOT PUBLISHED.** Private GitHub remote only; no GitHub Pages.

## Pinned kernel binary
```
sha256(wasm/seal.wasm) = ebd17c14668176612c49f6e2940b23df82a2c1a7cdef6759f0d6276ae997e9d0
size = 3,562,510 bytes
```
The page recomputes this in-browser on load (SubtleCrypto, or a bundled pure-JS
SHA-256 fallback on non-secure origins) and refuses to emit receipts on mismatch.

## Checklist (must all hold to publish)

- [x] **wasm sha256 matches pin** — `sha256sum wasm/seal.wasm` = pinned value above.
- [x] **No private path / repo / commit / author leak in the binary** — `strings` over
      `wasm/seal.wasm` shows zero `seal-host`, private-dev, `wasm-spike`, hostname,
      `/home/…`, `/Users/…`, `/root/…`, `Kernels/`, `Host/`, `Ffi`, or `G1`–`G7`.
- [x] **Embedded wasm strings are public-only** — the binary exposes just (a) public
      kernel type names `SealCore.Decision.*`, `SealCore.Event.*`, `SealV2.AST.*`
      (names from the *published* `mcp-seal`; AST names are generic JSON constructors)
      and (b) Lean compiler runtime strings (`runElab`, `delta`, …, and a Lean-internal
      40-hex constant `7e01a1bf…` confirmed **not** a git object in any repo).
- [x] **Symbol-scrub status** — no *private* symbols are present, so no scrub is
      required. Stripping the public Lean type names would need a kernel recompile
      (out of scope; reuse-as-is). A future hardening pass can rebuild with symbol
      stripping in the private build pipeline.
- [x] **No private markers in code** — grep over all shipped JS/HTML/CSS for
      the private-marker set (internal repo names `seal-host | mcp-seal-dev |
      wasm-spike | record-core`, milestone tags `M5..M8`, plus your build
      machine's hostname and `$HOME` path — substitute the concrete values
      locally; they are deliberately not written into this tracked file)
      returns nothing.
- [x] **No private markers in the spec** — `docs/SEAL-MEDIATION-PROFILE-L0.md` names
      nothing private; higher layers are excluded generically, not described.
- [x] **README / NOTICE describe only public artifacts.**
- [x] **Node test harness is TEST-ONLY** — see below.
- [x] **Receipt determinism** — `node test/receipt-harness.cjs` → all PASS, block
      receipt byte-identical across runs (4589 bytes, schema v1).

### TEST-ONLY: `test/*.cjs` and `differential/`
The Node scripts under `test/` (`receipt-format.test.cjs`, `receipt-harness.cjs`,
`cross-receipt.test.cjs`, `receipt-verify.test.cjs`) and `differential/` are
**verification harnesses, not runtime**. `index.html` never loads them; the browser
never sees them; they ship no user-facing behaviour. They run the *same public wasm*
under Node only to reproduce receipts, confirm determinism, and prove the tampered
/ negative verification paths reject. Each has a prominent TEST-ONLY header and no
third-party dependencies. A reviewer MUST NOT mistake them for production code. The
shipped runtime is exactly: `index.html`, `app.js`, `receipt.js`,
`receipt-format.js`, `kernel.js`, `seal-config.js`, `seal-wasm.js`, `corpus.js`,
`style.css`, `wasm/seal.{js,wasm}`.

## Re-run the audit
```sh
sha256sum wasm/seal.wasm    # = pinned value

# no private markers in any shipped file (docs intentionally NAME the boundary, so
# exclude README/AUDIT/spec from the code scan):
# substitute <hostname> and <home-path> with your build machine's values —
# the concrete strings are deliberately kept out of this tracked file:
grep -rEni "seal-host|mcp-seal-dev|wasm-spike|<hostname>|<home-path>|record.?core" \
  --exclude-dir=.git --exclude=README.md --exclude=AUDIT.md \
  --exclude=SEAL-MEDIATION-PROFILE-L0.md --binary-files=without-match .
echo "exit=$?  (1 = clean / no matches)"

# no private markers in the binary:
strings -n 5 wasm/seal.wasm | grep -Ei 'seal-host|mcp-seal-dev|wasm-spike|/home/|/Users/'

# receipts reproduce + determinism holds:
node test/receipt-harness.cjs
```

## Flip-public procedure (manual, separately authorised — NOT run here)
The public flip is **out of scope** for this build and MUST be performed deliberately
by the owner after re-running the checklist. Steps, when authorised:
1. Re-run the full audit above; confirm every box holds.
2. Create the public GitHub repo (`velvetmonkey/seal-check`) and add it as `origin`.
3. `git push origin master` and `git push origin seal-check-v0` (the tag).
4. (Optional) enable GitHub Pages on the default branch; add `.nojekyll` so `/wasm/`
   serves; confirm the wasm loads over HTTPS and `kernel_identity.self_verified_in_browser`
   is `true` on the live URL.
5. Re-verify the live URL end-to-end (kernel pill, block/allow, replay 5/5, badge,
   conformance map).

Until all five are done by the owner: **private, no remote, not published.**
