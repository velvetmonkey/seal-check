// SPDX-License-Identifier: Apache-2.0
//
// ============================ TEST-ONLY — NOT SHIPPED ========================
// Fleet P0 teeth (parity with seal-assurance-kit 706d644 / forged-binding):
// a KERNEL-LESS forged unparseable ALLOW must NEVER be stamped AUTHORISED /
// exit 0 by the seal-check CLI. It lands on the DISTINCT reduced-scope state
// (exit 4). Three states kept apart: INVALID(1) != REDUCED-SCOPE(4) != VERIFIED(0).
//
// The forge reuses a real, Ed25519-signed signed_config from a fixture and
// pins its pubkey, so the config-signature layer passes — exactly the attack
// the goal describes (a forge reusing a public signed_config still must not
// reach VERIFIED). A config-LESS variant is the harder hard-FAIL leg.
//
// Run:  node test/unparseable-forge.test.cjs
// ============================================================================
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const ROOT = path.resolve(__dirname, "..");

// --- browser shims (same wasm-glue pattern as receipt-verify.test.cjs) ------
globalThis.require = require;
globalThis.__dirname = path.join(ROOT, "wasm");
(0, eval)(fs.readFileSync(path.join(ROOT, "wasm", "seal.js"), "utf8"));
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

// The legit fixture supplies the Ed25519-signed config the forge reuses.
const FIX = JSON.parse(fs.readFileSync(
  path.join(__dirname, "fixtures", "unparseable-block.receipt.json"), "utf8"));

// A kernel-less forged unparseable ALLOW: every field attacker-chosen and
// internally self-consistent (audit maps allow->ALLOW, certs match, and the
// audit's own request_sha256 equals the receipt's), reusing the fixture's
// real signed_config + kernel_config + kernel_identity. No kernel ever ran.
function forgedUnparseableAllow() {
  const H = crypto.createHash("sha256")
    .update('{"attacker":"chosen raw line the kernel never judged"}').digest("hex");
  const certs = [{ certHash: "111", kernel: "safety", reason: "forged", verdict: "allow" }];
  const audit = { certs, epoch: 1, request_sha256: H, tool: "db.execute", verdict: "allow" };
  const emitted = JSON.stringify({
    audit: JSON.stringify(audit),
    response: '{"id":1,"jsonrpc":"2.0","result":{"content":[],"isError":false}}\n',
    route: "forward",
  });
  return {
    seal_receipt: "v2", now: 1784110716264, request_sha256: H,
    request_parse_error: "cannot parse mediated request for receipt: attacker-crafted unparseable line",
    bypass: false, verdict: "ALLOW", authorization: "explicit_policy_allow",
    reason: "forged explicit policy allow", deny_kernel: null, certs, emitted_bytes: emitted,
    kernel_identity: FIX.kernel_identity,
    host_identity: FIX.host_identity,
    asserted_provenance: FIX.asserted_provenance,
    signed_config: FIX.signed_config,
    kernel_config: FIX.kernel_config,
    granted_capabilities: [],
  };
}

// verify-file.cjs hard-fails any non-canonical serialization, so write the
// forge exactly as the shipped verifier expects (this also means the forge is
// "built via assembleReceiptV2", per the goal).
function writeCanonical(dir, name, receiptObj, F) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, JSON.stringify(F.assembleReceiptV2(receiptObj), null, 2) + "\n");
  return file;
}

(async () => {
  const cfg = await import(path.join(ROOT, "seal-config.js"));
  const K = await import(path.join(ROOT, "kernel.js"));
  const R = await import(path.join(ROOT, "receipt.js"));
  const F = await import(path.join(ROOT, "receipt-format.js"));

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-check-forge-"));
  const cli = (...args) => spawnSync(process.execPath,
    [path.join(ROOT, "test", "verify-file.cjs"), ...args], { encoding: "utf8" });

  // --- Leg (a): NON-VACUITY. The forge genuinely reaches the reporting seam.
  // If it were rejected at shape, the CLI leg would prove nothing.
  const forge = F.assembleReceiptV2(forgedUnparseableAllow());
  const vr = await R.verifyReceipt(JSON.parse(JSON.stringify(forge)), { expectedConfigPubkey: cfg.PUBKEY });
  check("forge non-vacuity: format ok (reaches the reporting seam)", vr.formatOk === true,
    (vr.formatErrors || []).join("; "));
  check("forge non-vacuity: reduced-scope outcome, config signature accepted",
    vr.outcome === "authorised-unparseable" && vr.signature_valid === true && vr.allGood === false, vr.outcome);

  // --- Leg (b): the config-reusing forge is REDUCED SCOPE at the CLI, never a pass.
  const forgeFile = writeCanonical(dir, "forge-allow.json", forgedUnparseableAllow(), F);
  const cForge = cli(forgeFile, "--expected-config-pubkey", cfg.PUBKEY);
  check("forge CLI: exits 4 REDUCED SCOPE, never 0",
    cForge.status === 4 && cForge.stdout.includes("REDUCED SCOPE (authorised-unparseable)"),
    `status ${cForge.status}: ${cForge.stdout}${cForge.stderr}`);
  check("forge CLI: banner is NOT the AUTHORISED success line",
    !cForge.stdout.includes("AUTHORISED:") && !/^AUTHORISED /m.test(cForge.stdout),
    cForge.stdout);

  // --- Leg (c): config-LESS variant is a HARD FAIL (exit 1), not reduced scope.
  const configless = forgedUnparseableAllow();
  delete configless.signed_config;
  delete configless.kernel_config;
  const clFile = writeCanonical(dir, "forge-configless.json", configless, F);
  const cCl = cli(clFile, "--expected-config-pubkey", cfg.PUBKEY);
  check("config-less forge CLI: hard FAIL exit 1, never 0/4",
    cCl.status === 1, `status ${cCl.status}: ${cCl.stdout}${cCl.stderr}`);

  // --- Leg (d): the LEGIT unparseable fixture stays honest reduced-scope,
  // never a false hard-failure. INVALID(1) != REDUCED-SCOPE(4).
  const legitFile = path.join(__dirname, "fixtures", "unparseable-block.receipt.json");
  const cLegit = cli(legitFile, "--expected-config-pubkey", cfg.PUBKEY);
  check("legit unparseable CLI: exits 4 REDUCED SCOPE, not a hard failure",
    cLegit.status === 4 && cLegit.stdout.includes("REDUCED SCOPE (authorised-unparseable)")
      && !cLegit.stderr.includes("FAIL NOT VERIFIED"),
    `status ${cLegit.status}: ${cLegit.stdout}${cLegit.stderr}`);

  // --- Leg (e): BLUE control — a genuine parseable receipt still verifies (exit 0).
  const call = {
    tool: "store.update", args: { op: "orset.add", key: "k1" },
    approvals: [cfg.guardTarget("store.update", { op: "orset.add", key: "k1" })], now: 1000,
  };
  const res = await K.decideRaw(cfg.CFG_STANDARD, call);
  const sha = await K.verifyKernelSha();
  const genuine = K.canonicalReceiptJson(
    K.buildReceipt({ call, config: cfg.CFG_STANDARD, parsed: res.parsed, raw: res.raw, sha, signedConfig: res.signedConfig }));
  const blueFile = path.join(dir, "blue-allow.json");
  fs.writeFileSync(blueFile, genuine);
  const cBlue = cli(blueFile, "--expected-config-pubkey", cfg.PUBKEY);
  check("blue control CLI: genuine parseable receipt exits 0 AUTHORISED",
    cBlue.status === 0 && cBlue.stdout.includes("AUTHORISED: signed by pinned operator key"),
    `status ${cBlue.status}: ${cBlue.stdout}${cBlue.stderr}`);

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(failures === 0 ? "\nUNPARSEABLE-FORGE PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
