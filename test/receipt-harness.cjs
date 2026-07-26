// SPDX-License-Identifier: Apache-2.0
//
// ============================ TEST-ONLY — NOT SHIPPED ========================
// This file is a verification harness. It is NOT part of the seal-check runtime:
// index.html never loads it, the browser never sees it, and it ships no behaviour
// to users. Its only job is to run the SAME public wasm kernel under Node so a
// reviewer can reproduce the exact decision receipts off-browser and confirm
// determinism (the Node output is byte-identical to the in-browser receipt).
//
// Why eval(): wasm/seal.js is a classic-script MODULARIZE build that assigns a
// global `SealModule` and exports nothing, so under Node it is evaluated once to
// obtain that global factory. It loads only the project's own public artifact.
// No third-party dependencies; Node built-ins only.
//
// Run:  node test/receipt-harness.cjs
// ============================================================================
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const ROOT = path.resolve(__dirname, "..");

globalThis.require = require;            // the wasm glue's NODE branch needs these
globalThis.__dirname = path.join(ROOT, "wasm");
(0, eval)(fs.readFileSync(path.join(ROOT, "wasm", "seal.js"), "utf8")); // -> globalThis.SealModule
const SealModule = globalThis.SealModule;

(async () => {
  const cfg = await import(path.join(ROOT, "seal-config.js"));
  const K = await import(path.join(ROOT, "kernel.js"));
  const M = await SealModule({ locateFile: (p) => path.join(ROOT, "wasm", p), print() {}, printErr() {} });
  const sha = { computed: K.KERNEL_WASM_SHA256, pinned: K.KERNEL_WASM_SHA256, match: true };

  const F = await import(path.join(ROOT, "receipt-format.js"));

  const decide = async (config, call) => {
    const { tool, args, approvals = [] } = call;
    const signedConfig = await cfg.buildSignedConfig(config);
    const ir = JSON.parse(M.ccall("seal_init", "string", ["string", "string"], [signedConfig.envelope, signedConfig.pubkey]));
    if (ir.ok !== true) throw new Error("seal_init failed");
    const step = cfg.buildStepInput({ tool, args, approvals });
    const raw = M.ccall("seal_decide", "string", ["string"], [step]);
    return K.canonicalReceiptJson(K.buildReceipt({
      call: { tool, args, approvals }, config, parsed: cfg.parseVerdict(raw, tool), raw, sha, signedConfig,
    }));
  };

  const block = await decide(cfg.CFG_STANDARD, { tool: "db.execute", args: { database: "prod", sql: "drop table users" }, approvals: [] });
  const allow = await decide(cfg.CFG_STANDARD, { tool: "store.update", args: { op: "orset.add", key: "k1" }, approvals: [cfg.stableHash(["store.update", "store"])] });

  const expectSha = "d7d81e277ba0b5e9df385129d86abf6f7469e6da2a65bb2ec35626caa44ea2be";
  let ok = true;
  const check = (name, cond) => { console.log(`${cond ? "PASS" : "FAIL"}  ${name}`); ok = ok && cond; };
  const blockR = JSON.parse(block), allowR = JSON.parse(allow);
  const signed = await cfg.buildSignedConfig(cfg.CFG_STANDARD);
  const nodeKey = crypto.createPrivateKey({
    key: Buffer.from(
      "302e020100300506032b657004220420" +
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex"),
    type: "pkcs8", format: "der",
  });
  const nodeSignature = crypto.sign(null, Buffer.from(signed.payload, "utf8"), nodeKey).toString("hex");
  check("browser WebCrypto signature = Node crypto.sign signature",
    signed.signature === nodeSignature);
  check("signed payload is the exact compact config string",
    signed.payload === JSON.stringify(cfg.CFG_STANDARD));
  check("block verdict = BLOCK", blockR.verdict === "BLOCK");
  check("allow verdict = ALLOW", allowR.verdict === "ALLOW");
  check("schema v2 discriminator", blockR.seal_receipt === "v2" && allowR.seal_receipt === "v2");
  check("validateReceipt: both receipts well-formed v2",
    F.validateReceipt(blockR).ok && F.validateReceipt(allowR).ok);
  check("hard split: kernel_identity carries no toolchain/axioms",
    !("lean_toolchain" in blockR.kernel_identity) && !("axioms" in blockR.kernel_identity));
  check("canonical_request_sha256 = derived from (tool, arguments)",
    blockR.canonical_request_sha256 === F.canonicalRequestSha256(blockR.tool, blockR.arguments));
  check("kernel sha pinned", blockR.kernel_identity.wasm_sha256 === expectSha);
  check("asserted_provenance NOT verified", allowR.asserted_provenance.verified_in_browser === false);
  check("opaque grant carried for raw-target approval",
    allowR.granted_capabilities.length === 1 &&
    allowR.granted_capabilities[0].target === cfg.stableHash(["store.update", "store"]));
  // determinism: re-run identical input -> byte-identical receipt
  const block2 = await decide(cfg.CFG_STANDARD, { tool: "db.execute", args: { database: "prod", sql: "drop table users" }, approvals: [] });
  check("determinism: block == block2 (byte-identical)", block === block2);

  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error("ERR", e.message); process.exit(1); });
