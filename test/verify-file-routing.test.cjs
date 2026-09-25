// SPDX-License-Identifier: Apache-2.0
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const cli = path.join(__dirname, "verify-file.cjs");
const examples = path.join(root, "examples");
const protect = path.join(examples, "protect-block.receipt.json");
const protectKey = fs.readFileSync(path.join(examples, "protect-signer.pub"), "utf8").trim();
const decision = path.join(examples, "allow.receipt.json");
const decisionKey = JSON.parse(fs.readFileSync(decision, "utf8")).signed_config.pubkey;
const run = (file, key) => spawnSync(process.execPath, [cli, file, ...(key ? ["--expected-config-pubkey", key] : [])], { cwd: root, encoding: "utf8" });
const scratch = fs.mkdtempSync(path.join(root, ".verify-file-routing-"));
const write = (name, text) => { const file = path.join(scratch, name); fs.writeFileSync(file, text); return file; };

(async () => {
  try {
    globalThis.require = require;
    globalThis.__dirname = path.join(root, "wasm");
    (0, eval)(fs.readFileSync(path.join(root, "wasm", "seal.js"), "utf8"));
    globalThis.window = globalThis;
    globalThis.fetch = async (p) => {
      const bytes = fs.readFileSync(path.join(root, p));
      return { ok: true, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
    };
    const { classifyReceiptDocument } = await import(path.join(root, "receipt-format.js"));
    const { verify } = await import(path.join(root, "protect-receipt.js"));
    const text = fs.readFileSync(protect, "utf8");
    assert.equal(classifyReceiptDocument(text).family, "decision");
    const browser = await verify(text, { publicKeyHex: protectKey });
    assert.equal(browser.validate && browser.signature && browser.replay, true);
    const valid = run(protect, protectKey);
    assert.equal(valid.status, 3, valid.stderr);
    assert.match(valid.stdout, /Verifier-local verdict   REPRODUCED/);

    const receipt = JSON.parse(text);
    for (const field of ["verdict", "replay"]) {
      const tampered = structuredClone(receipt);
      if (field === "verdict") tampered.verdict = tampered.verdict === "BLOCK" ? "ALLOW" : "BLOCK";
      else tampered.replay.args_sha256 = (tampered.replay.args_sha256[0] === "0" ? "1" : "0") + tampered.replay.args_sha256.slice(1);
      assert.equal(run(write(`${field}.json`, JSON.stringify(tampered)), protectKey).status, 1, field);
    }
    assert.equal(run(decision).status, 3, "decision unpinned");
    assert.equal(run(decision, decisionKey).status, 0, "decision pinned");
    assert.equal(run(decision, "0".repeat(64)).status, 1, "decision wrong pin");
    const spineKey = fs.readFileSync(path.join(examples, "spine-signer.pub"), "utf8").trim();
    assert.equal(run(path.join(examples, "spine-allow.receipt.json"), spineKey).status, 3, "Spine signature");
    console.log("verify-file routing: Protect/browser agreement, tamper refusals, decision exits, Spine pass");
  } finally {
    fs.rmSync(scratch, { recursive: true });
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
