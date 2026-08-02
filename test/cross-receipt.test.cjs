// SPDX-License-Identifier: Apache-2.0
//
// ============================ TEST-ONLY — NOT SHIPPED ========================
// Cross-tool receipt test, seal-check half (spec §10.4).
//
// Produces a schema-v1 receipt through the REAL wasm kernel via the shipped
// producer (kernel.js buildReceipt), pins it as a byte-stable fixture, and
// verifies it through the shipped verifier (receipt.js verifyReceipt) under
// Node. The byte-identical fixture is vendored into
// seal-assurance-kit/fixtures/receipt-crosstool.json, where `seal verify`
// must also pass it — one receipt, both verifiers.
//
// Node shims: kernel.js expects a browser (window.SealModule, fetch of the
// wasm, SubtleCrypto). window/fetch are shimmed; Node >= 20 provides
// crypto.subtle natively.
//
// Run:  node test/cross-receipt.test.cjs            (verify against fixture)
//       node test/cross-receipt.test.cjs --update   (regenerate fixture)
// ============================================================================
const fs = require("fs");
const path = require("path");
const ROOT = path.resolve(__dirname, "..");
const FIXTURE = path.join(__dirname, "fixtures", "cross-receipt.json");
const EXAMPLE = path.join(ROOT, "examples", "allow.receipt.json");

// --- browser shims (same wasm-glue pattern as receipt-harness.cjs) ----------
globalThis.require = require;
globalThis.__dirname = path.join(ROOT, "wasm");
(0, eval)(fs.readFileSync(path.join(ROOT, "wasm", "seal.js"), "utf8")); // -> globalThis.SealModule
globalThis.window = globalThis;
globalThis.fetch = async (p) => {
  const buf = fs.readFileSync(path.join(ROOT, p));
  return { arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) };
};

let failures = 0;
function check(name, cond, detail = "") {
  if (!cond) failures++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond || !detail ? "" : `   (${detail})`}`);
}

(async () => {
  const cfg = await import(path.join(ROOT, "seal-config.js"));
  const K = await import(path.join(ROOT, "kernel.js"));
  const R = await import(path.join(ROOT, "receipt.js"));

  // Produce through the SHIPPED pipeline: decideRaw + buildReceipt.
  const call = {
    tool: "store.update", args: { op: "orset.add", key: "k1" },
    approvals: [cfg.guardTarget("store.update", { op: "orset.add", key: "k1" })], now: 1000,
  };
  const res = await K.decideRaw(cfg.CFG_STANDARD, call);
  const sha = await K.verifyKernelSha();
  check("kernel self-verified against pin", sha.match);
  const receipt = K.buildReceipt({ call, config: cfg.CFG_STANDARD, parsed: res.parsed, raw: res.raw, sha, signedConfig: res.signedConfig });
  const json = K.canonicalReceiptJson(receipt);

  // Pin the fixture (byte-stable: same input -> identical bytes).
  if (process.argv.includes("--update") || !fs.existsSync(FIXTURE)) {
    fs.mkdirSync(path.dirname(FIXTURE), { recursive: true });
    fs.writeFileSync(FIXTURE, json);
    console.log(`wrote ${FIXTURE}`);
    fs.mkdirSync(path.dirname(EXAMPLE), { recursive: true });
    fs.writeFileSync(EXAMPLE, json);
    console.log(`wrote ${EXAMPLE}`);
  }
  check("receipt byte-identical to committed fixture", json === fs.readFileSync(FIXTURE, "utf8"),
    "regenerate with --update if the producer changed intentionally");

  // Verify through the SHIPPED verifier.
  const out = await R.verifyReceipt(JSON.parse(json), { expectedConfigPubkey: cfg.PUBKEY });
  check("verifyReceipt: schema valid (v2)", out.formatOk && out.formatVersion === "v2",
    (out.formatErrors || []).join("; "));
  check("verifyReceipt: kernel sha match", out.kernelShaMatch === true);
  check("verifyReceipt: request hash match", out.requestHashMatch === true);
  check("verifyReceipt: verdict re-derived (ALLOW)", out.verdictMatch === true && out.rederived === "ALLOW");
  check("verifyReceipt: emitted bytes byte-identical", out.emittedBytesMatch === true);
  check("verifyReceipt: real config signature accepted", out.signature_valid === true);
  check("verifyReceipt: replay consistent", out.kernel_replay_consistent === true);
  check("verifyReceipt: pinned authority trusted", out.authority_trusted === true);
  check("verifyReceipt: authorised/allGood", out.outcome === "authorised" && out.allGood === true);

  console.log(failures === 0 ? "\nCROSS-RECEIPT (seal-check half) PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
