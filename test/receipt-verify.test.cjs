// SPDX-License-Identifier: Apache-2.0
//
// ============================ TEST-ONLY — NOT SHIPPED ========================
// Negative-path tests for the shipped verifier (receipt.js verifyReceipt):
// a genuine receipt verifies, and every tampered variant is REJECTED with the
// matching check flag false. This is "verify, don't trust" made executable —
// the rejection paths, not just the happy path.
//
// Also covers callSummary (real receipts must never summarize as "undefined")
// and the base64url deep-link decode roundtrip.
//
// Run:  node test/receipt-verify.test.cjs
// ============================================================================
const fs = require("fs");
const path = require("path");
const ROOT = path.resolve(__dirname, "..");

// --- browser shims (same wasm-glue pattern as cross-receipt.test.cjs) -------
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
const flipHexChar = (s) => (s[0] === "0" ? "1" : "0") + s.slice(1);

(async () => {
  const cfg = await import(path.join(ROOT, "seal-config.js"));
  const K = await import(path.join(ROOT, "kernel.js"));
  const R = await import(path.join(ROOT, "receipt.js"));

  // Produce a genuine receipt through the SHIPPED pipeline.
  const call = {
    tool: "store.update", args: { op: "orset.add", key: "k1" },
    approvals: [cfg.stableHash(["store.update", "store"])], now: 1000,
  };
  const res = await K.decideRaw(cfg.CFG_STANDARD, call);
  const sha = await K.verifyKernelSha();
  check("kernel self-verified against pin", sha.match);
  const genuine = JSON.parse(K.canonicalReceiptJson(
    K.buildReceipt({ call, config: cfg.CFG_STANDARD, parsed: res.parsed, raw: res.raw, sha })));
  const clone = () => JSON.parse(JSON.stringify(genuine));

  // Baseline: the genuine receipt verifies.
  const ok = await R.verifyReceipt(clone());
  check("genuine receipt: allGood", ok.allGood === true, (ok.formatErrors || []).join("; "));

  // Tamper 1: verdict flipped (shape stays valid; re-derivation must catch it).
  const tVerdict = clone();
  tVerdict.verdict = tVerdict.verdict === "ALLOW" ? "BLOCK" : "ALLOW";
  const rV = await R.verifyReceipt(tVerdict);
  check("tampered verdict: shape still v1", rV.formatOk === true);
  check("tampered verdict: verdictMatch false", rV.verdictMatch === false);
  check("tampered verdict: allGood false", rV.allGood === false);

  // Tamper 2: kernel identity points at a different binary.
  const tSha = clone();
  tSha.kernel_identity.wasm_sha256 = flipHexChar(tSha.kernel_identity.wasm_sha256);
  const rS = await R.verifyReceipt(tSha);
  check("tampered kernel sha: kernelShaMatch false", rS.kernelShaMatch === false);
  check("tampered kernel sha: allGood false", rS.allGood === false);

  // Tamper 3: request fingerprint altered.
  const tReq = clone();
  tReq.canonical_request_sha256 = flipHexChar(tReq.canonical_request_sha256);
  const rR = await R.verifyReceipt(tReq);
  check("tampered request sha: requestHashMatch false", rR.requestHashMatch === false);
  check("tampered request sha: allGood false", rR.allGood === false);

  // Tamper 4: emitted decision bytes altered.
  const tBytes = clone();
  tBytes.emitted_bytes = tBytes.emitted_bytes + "x";
  const rB = await R.verifyReceipt(tBytes);
  check("tampered emitted bytes: emittedBytesMatch false", rB.emittedBytesMatch === false);
  check("tampered emitted bytes: allGood false", rB.allGood === false);

  // Tamper 5: arguments swapped for different ones (stored canonical_request
  // no longer matches the derived line — must die at shape validation).
  const tArgs = clone();
  tArgs.arguments = { op: "orset.add", key: "SOMETHING_ELSE" };
  const rA = await R.verifyReceipt(tArgs);
  check("tampered arguments: rejected", rA.allGood === false);

  // Bypass receipt: NOT MEDIATED, never "verified".
  const bypass = {
    seal_receipt: "v1", tool: "db.execute", arguments: { operation: "DELETE", table: "users" },
    canonical_request_sha256: genuine.canonical_request_sha256, bypass: true,
    verdict: "ALLOW", reason: "gate removed (control)",
    kernel_identity: { wasm_sha256: null, self_verified: false },
  };
  const rBy = await R.verifyReceipt(bypass);
  check("bypass receipt: shape valid", rBy.formatOk === true, (rBy.formatErrors || []).join("; "));
  check("bypass receipt: mediated false", rBy.mediated === false);
  check("bypass receipt: allGood false", rBy.allGood === false);

  // callSummary: the demo shape keeps its phrasing; real receipts never "undefined".
  const sDemo = R.callSummary(bypass);
  check("callSummary: demo shape recognized", sDemo.demo === true && sDemo.operation === "DELETE" && sDemo.table === "users");
  const sReal = R.callSummary(genuine);
  check("callSummary: real receipt is generic tool+args", sReal.demo === false && sReal.tool === "store.update");
  check("callSummary: no 'undefined' anywhere", !JSON.stringify(sReal).includes("undefined"));
  const sEmpty = R.callSummary({});
  check("callSummary: degenerate receipt still safe", sEmpty.demo === false && sEmpty.tool === "unknown tool");

  // Deep-link decode roundtrip (the #receipt= mechanism).
  const json = JSON.stringify(genuine);
  const b64url = Buffer.from(json, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  check("b64url roundtrip: decodes to the same receipt", R.b64urlToStr(b64url) === json);
  let threw = false;
  try { R.b64urlToStr("!!!not-base64url!!!"); } catch { threw = true; }
  check("b64url: malformed input throws (caught by the UI as a decode error)", threw);

  console.log(failures === 0 ? "\nRECEIPT-VERIFY (negative paths) PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
