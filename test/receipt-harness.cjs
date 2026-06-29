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

  const decide = (config, { tool, args, approvals = [] }) => {
    const ir = JSON.parse(M.ccall("seal_init", "string", ["string", "string"], [cfg.buildEnvelope(config), cfg.PUBKEY]));
    if (ir.ok !== true) throw new Error("seal_init failed");
    const step = cfg.buildStepInput({ tool, args, approvals });
    const raw = M.ccall("seal_decide", "string", ["string"], [step]);
    const s = JSON.parse(step);
    const input = { request_line: s.line, now: s.now, approvals: approvals.map(String) };
    return K.canonicalReceiptJson(K.buildReceipt({ input, parsed: cfg.parseVerdict(raw, tool), raw, sha }));
  };

  const block = decide(cfg.CFG_STANDARD, { tool: "db.execute", args: { database: "prod", sql: "drop table users" }, approvals: [] });
  const allow = decide(cfg.CFG_STANDARD, { tool: "store.update", args: { op: "orset.add", key: "k1" }, approvals: [cfg.stableHash(["store.update", "store"])] });

  const expectSha = "1cc765c7de2cead88eda2e8e5f5af5a5e070f35a767916e754b873733562c70a";
  let ok = true;
  const check = (name, cond) => { console.log(`${cond ? "PASS" : "FAIL"}  ${name}`); ok = ok && cond; };
  check("block verdict = BLOCK", JSON.parse(block).verdict === "BLOCK");
  check("allow verdict = ALLOW", JSON.parse(allow).verdict === "ALLOW");
  check("block receipt = 2062 bytes", block.length === 2062);
  check("kernel sha pinned", JSON.parse(block).kernel_identity.wasm_sha256 === expectSha);
  check("asserted_provenance NOT verified", JSON.parse(allow).asserted_provenance.verified_in_browser === false);
  // determinism: re-run identical input -> byte-identical receipt
  const block2 = decide(cfg.CFG_STANDARD, { tool: "db.execute", args: { database: "prod", sql: "drop table users" }, approvals: [] });
  check("determinism: block == block2 (byte-identical)", block === block2);

  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error("ERR", e.message); process.exit(1); });
