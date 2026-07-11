# seal-check — Claim Audit Findings

**Scope**: README + docs/ (CONFORMANCE, TCB, etc.) + test/ and wasm entry. Sampled claims from opener, TL;DR, "what happens", non-claims, assurance statement.

**Backed by**: test/receipt-verify.test.cjs (tamper suite), kernel + receipt-format, differential harness, seal-assurance-kit fixtures, conformance.

**Collar**: All truthbox, non-claims, "not the whole system", "compatible", "tamper-EVIDENT" etc. preserved verbatim.

## Sampled Claims

| Claim | Backed? | File:line / evidence | Action |
|-------|---------|----------------------|--------|
| Paste a tool-call or receipt; the page re-derives Allow/Block in browser; tampered receipt fails in front of you. | Yes (implemented + tested) | index.html + receipt.js + test/receipt-verify.test.cjs (tamper cases expect fail); wasm bundle | keep |
| Nothing you paste leaves the page. | Yes | receipt.js (pure local re-derive) | keep |
| The page hashes its bundled wasm, checks pinned identity, re-runs the same kernel. | Yes (tested) | seal-check code + seal-assurance-kit conformance vectors | keep |
| Seal proves the KERNEL, not whole deployed; binaries tied by conformance. | Yes (documented + true) | README truthbox + non-claims (verbatim), docs/CONFORMANCE.md | keep |
| Tamper-EVIDENT audit, not impossible. | Yes (documented) | docs/LIMITATIONS (via family) | keep |

## NEEDS BEN
- Full browser manual tamper demo run in this session (static + test code provide the verification; captured in prior evidence).
- Exhaustive wasm hash vs every conformance entry.

All sampled claims backed or are preserved honesty labels. No new claims.

See docs/ and family CLAIMS-MATRIX.