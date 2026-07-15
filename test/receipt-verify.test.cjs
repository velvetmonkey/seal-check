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
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
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
    K.buildReceipt({ call, config: cfg.CFG_STANDARD, parsed: res.parsed, raw: res.raw, sha, signedConfig: res.signedConfig })));
  const clone = () => JSON.parse(JSON.stringify(genuine));

  // Baseline: the genuine receipt verifies.
  const unpinned = await R.verifyReceipt(clone());
  check("genuine receipt: signature valid", unpinned.signature_valid === true, unpinned.rederiveError || "");
  check("genuine receipt: replay consistent", unpinned.kernel_replay_consistent === true);
  check("genuine receipt: unpinned is not allGood", unpinned.outcome === "unpinned" && unpinned.allGood === false);
  check("genuine receipt: freshness carried, rollback deferred",
    unpinned.config_freshness?.value === 1 && unpinned.config_freshness.rollback_enforced === false);
  const ok = await R.verifyReceipt(clone(), { expectedConfigPubkey: cfg.PUBKEY });
  check("genuine receipt: pinned authority authorised", ok.authority_trusted === true && ok.outcome === "authorised" && ok.allGood === true,
    (ok.formatErrors || []).join("; "));

  // Opaque grants are this box's defining property (fire-your-own-target
  // approvals are raw commitments): surfaced informationally, never gating.
  check("genuine receipt: 1 opaque grant counted", ok.opaqueGrants === 1, String(ok.opaqueGrants));
  check("genuine receipt: hasOpaqueGrants true", ok.hasOpaqueGrants === true);

  // A no-grant receipt (BLOCK, empty approvals) carries nothing opaque.
  const cleanCall = { tool: "db.execute", args: { database: "prod", sql: "drop table users" }, approvals: [], now: 1000 };
  const cleanRes = await K.decideRaw(cfg.CFG_STANDARD, cleanCall);
  const cleanReceipt = JSON.parse(K.canonicalReceiptJson(
    K.buildReceipt({ call: cleanCall, config: cfg.CFG_STANDARD, parsed: cleanRes.parsed, raw: cleanRes.raw, sha, signedConfig: cleanRes.signedConfig })));
  const rClean = await R.verifyReceipt(cleanReceipt, { expectedConfigPubkey: cfg.PUBKEY });
  check("no-grant receipt: verdict BLOCK", cleanReceipt.verdict === "BLOCK");
  check("no-grant receipt: allGood", rClean.allGood === true, (rClean.formatErrors || []).join("; "));
  check("no-grant receipt: opaqueGrants 0", rClean.opaqueGrants === 0, String(rClean.opaqueGrants));
  check("no-grant receipt: hasOpaqueGrants false", rClean.hasOpaqueGrants === false);

  // Authority is independent of crypto + replay: a wrong pin leaves those
  // dimensions true but hard-fails the overall outcome.
  const wrongPin = await R.verifyReceipt(clone(), { expectedConfigPubkey: "0".repeat(64) });
  check("wrong pin: signature remains valid", wrongPin.signature_valid === true);
  check("wrong pin: replay remains consistent", wrongPin.kernel_replay_consistent === true);
  check("wrong pin: unauthorised failure", wrongPin.authority_trusted === false && wrongPin.outcome === "failure" && wrongPin.allGood === false);

  const tSig = clone();
  tSig.signed_config.signature = flipHexChar(tSig.signed_config.signature);
  const rSig = await R.verifyReceipt(tSig, { expectedConfigPubkey: cfg.PUBKEY });
  check("tampered config signature: signature_valid false", rSig.signature_valid === false);
  check("tampered config signature: verdict not re-derived", rSig.verdictMatch === null && rSig.kernel_replay_consistent === false);

  const tPayload = clone();
  tPayload.signed_config.payload = tPayload.signed_config.payload.replace('"epoch":1', '"epoch":2');
  const rPayload = await R.verifyReceipt(tPayload, { expectedConfigPubkey: cfg.PUBKEY });
  check("flipped payload byte: binding fails", rPayload.bindingOk === false);
  check("flipped payload byte: verdict not re-derived", rPayload.verdictMatch === null && rPayload.kernel_replay_consistent === false);

  const tSwap = clone();
  tSwap.kernel_config.epoch = 2;
  const rSwap = await R.verifyReceipt(tSwap, { expectedConfigPubkey: cfg.PUBKEY });
  check("swapped displayed config: hard fails before replay",
    (rSwap.formatOk === false || rSwap.bindingOk === false) && rSwap.kernel_replay_consistent === false && rSwap.allGood === false);

  const tPolicyHash = clone();
  tPolicyHash.approval.policy_hash = "0".repeat(64);
  const rPolicyHash = await R.verifyReceipt(tPolicyHash, { expectedConfigPubkey: cfg.PUBKEY });
  check("approval policy_hash mismatch: rejected", rPolicyHash.formatOk === false && rPolicyHash.allGood === false);

  const tAuthority = clone(); tAuthority.authority_trusted = true;
  const rAuthority = await R.verifyReceipt(tAuthority, { expectedConfigPubkey: cfg.PUBKEY });
  check("receipt-supplied authority_trusted: rejected", rAuthority.formatOk === false && rAuthority.allGood === false);

  const withHostIdentity = clone();
  withHostIdentity.host_identity = {
    native_executable_sha256: "a".repeat(64), lean_ffi_sha256: "b".repeat(64), equivalence: "not_proven",
  };
  const rHost = await R.verifyReceipt(withHostIdentity, { expectedConfigPubkey: cfg.PUBKEY });
  check("valid-hex host_identity remains asserted/unbound", rHost.outcome === "authorised");
  withHostIdentity.host_identity.native_executable_sha256 = "nothex";
  const rBadHost = await R.verifyReceipt(withHostIdentity, { expectedConfigPubkey: cfg.PUBKEY });
  check("malformed host_identity rejected", rBadHost.formatOk === false && rBadHost.allGood === false);

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

  // CLI contract mirrors the authority tri-state all the way to process exit.
  const cliDir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-check-cli-"));
  const cliReceipt = path.join(cliDir, "allow.json");
  fs.writeFileSync(cliReceipt, K.canonicalReceiptJson(genuine));
  const cli = (...args) => spawnSync(process.execPath,
    [path.join(ROOT, "test", "verify-file.cjs"), ...args], { encoding: "utf8" });
  let cliRun = cli(cliReceipt, "--expected-config-pubkey", cfg.PUBKEY);
  check("verify-file CLI: matching pin exits 0/AUTHORISED",
    cliRun.status === 0 && cliRun.stdout.includes("AUTHORISED: signed by pinned operator key"));
  cliRun = cli(cliReceipt);
  check("verify-file CLI: absent pin exits 3/UNPINNED",
    cliRun.status === 3 && cliRun.stdout.includes("AUTHENTIC + REPLAY-CONSISTENT, authority NOT established"));
  cliRun = cli(cliReceipt, "--expected-config-pubkey", "0".repeat(64));
  check("verify-file CLI: wrong pin exits 1/unauthorised",
    cliRun.status === 1 && cliRun.stderr.includes("FAIL unauthorised config signer"));
  cliRun = cli(cliReceipt, "--expected-config-pubkey", "bad");
  check("verify-file CLI: malformed pin exits 2/usage",
    cliRun.status === 2 && cliRun.stderr.includes("usage:"));
  fs.rmSync(cliDir, { recursive: true, force: true });

  // --- §11.1 unparseable-request receipt: REAL seal-host receipt -------------
  // Produced by seal-host main @ 3a74dbf on the pinned 1e309 line
  // (test/host_path.rs:722 form): serde cannot re-parse it, the Lean kernel
  // mediates it. The verifier must report a DISTINCT reduced-scope state —
  // never requestHashMatch:true (the undefined === undefined false PASS this
  // test exists to prevent), and never a bare AUTHORISED.
  const unp = JSON.parse(fs.readFileSync(
    path.join(__dirname, "fixtures", "unparseable-block.receipt.json"), "utf8"));
  const cloneUnp = () => JSON.parse(JSON.stringify(unp));
  check("unparseable: callSummary names the raw-line state (never 'undefined')",
    R.callSummary(unp).unparseable === true && typeof R.callSummary(unp).rawLineShort === "string");
  const u = await R.verifyReceipt(cloneUnp(), { expectedConfigPubkey: cfg.PUBKEY });
  check("unparseable: format ok", u.formatOk === true, (u.formatErrors || []).join("; "));
  check("unparseable: requestHashMatch is null — its own state, NOT a false match",
    u.requestHashMatch === null);
  check("unparseable: raw line identity carried", u.rawLineIdentity === unp.request_sha256);
  check("unparseable: replay honestly unavailable", typeof u.replayUnavailable === "string");
  check("unparseable: kernel_replay_consistent stays false", u.kernel_replay_consistent === false);
  check("unparseable: config signature verified directly (Ed25519)", u.signature_valid === true);
  check("unparseable: kernel material self-consistent (audit verdict + certs)",
    u.kernelMaterialConsistent === true);
  check("unparseable: outcome authorised-unparseable, never bare authorised",
    u.outcome === "authorised-unparseable" && u.allGood === false, u.outcome);
  const uUnpinned = await R.verifyReceipt(cloneUnp());
  check("unparseable: without pin stays unpinned", uUnpinned.outcome === "unpinned");
  const uTampered = cloneUnp();
  uTampered.verdict = "ALLOW"; // audit says deny — material no longer self-consistent
  const ut = await R.verifyReceipt(uTampered, { expectedConfigPubkey: cfg.PUBKEY });
  check("unparseable: tampered verdict fails kernel-material consistency",
    ut.formatOk === false || (ut.kernelMaterialConsistent === false && ut.outcome === "failure"));
  const uFab = await R.verifyReceipt({ ...cloneUnp(), tool: "db.execute" });
  check("unparseable + fabricated tool rejected at shape", uFab.formatOk === false);

  // CLI: distinct state maps to exit 0 with the reduced-scope banner.
  const unpPath = path.join(__dirname, "fixtures", "unparseable-block.receipt.json");
  let cliUnp = cli(unpPath, "--expected-config-pubkey", cfg.PUBKEY);
  check("verify-file CLI: unparseable + pin exits 0 with raw-line-identity banner",
    cliUnp.status === 0 && cliUnp.stdout.includes("AUTHORISED (raw-line identity only)"),
    `status ${cliUnp.status}: ${cliUnp.stdout}${cliUnp.stderr}`);
  cliUnp = cli(unpPath);
  check("verify-file CLI: unparseable without pin exits 3/UNPINNED", cliUnp.status === 3);

  console.log(failures === 0 ? "\nRECEIPT-VERIFY (negative paths) PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
