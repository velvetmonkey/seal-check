# Conformance

Seal's deployment claim is byte identity over a corpus, not a theorem about every possible input.

The acceptance bridge lives in `seal-host/scripts/conformance_bridge.mjs`. Its Stage 3 gate compares:

- interpreted Lean model;
- native `.so` entry point;
- rebuilt wasm artifact;
- deployed Rust host record-chain behavior;
- JavaScript target-commitment mirrors used by the checker and demos.

The target commitment is lowercase 64-hex SHA-256 over `encodeParts(parts)`, where each part is framed as `<charCount>:<part>` using Lean/String code-point count, then encoded as UTF-8 before hashing. This is intentionally separate from the legacy UInt64 `certHash` audit helper.

What conformance says: for the corpus, the bodies emit byte-identical target hashes, decisions, audit bytes, and record chain heads.

What it does not say: Rust, wasm, JavaScript, browsers, compilers, or operating systems are proven correct for every possible input.

Local checks for this repo:

```sh
python3 -m http.server 8000
# open http://localhost:8000
node test/receipt-format.test.cjs
node test/receipt-harness.cjs
node test/cross-receipt.test.cjs
```
