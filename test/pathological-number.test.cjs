// SPDX-License-Identifier: Apache-2.0
//
// ============================ TEST-ONLY — NOT SHIPPED ========================
// Uniformity catalogue vector #4 — pathological JSON number, fail-closed.
//
// A wire line carrying a monster-exponent number (1e9999999999) used to split
// the fleet: the OLD d3067bc0 wasm returned classify-default passthrough — a
// mediation BYPASS in the browser lane. The ff1bfd68 repin closed it (guard
// carried forward unchanged by the current 28bb3ae7 kernel): the line is refused
// BEFORE Json.parse (Seal.JsonUtil.wireNumbersSafe) and the refuse route is
// `block`. This drives the SHIPPED in-browser wasm directly and pins: block,
// never passthrough, no crash — same input, same verdict as every fleet copy.
//
// Run:  node test/pathological-number.test.cjs
// ============================================================================
const fs = require("fs");
const path = require("path");
const ROOT = path.resolve(__dirname, "..");

// Same browser-glue shim as receipt-verify.test.cjs / cross-receipt.test.cjs.
globalThis.require = require;
globalThis.__dirname = path.join(ROOT, "wasm");
(0, eval)(fs.readFileSync(path.join(ROOT, "wasm", "seal.js"), "utf8")); // -> globalThis.SealModule
globalThis.window = globalThis;

const PATHOLOGICAL = "1e9999999999";
let failures = 0;
const check = (name, cond, detail = "") => {
  if (!cond) failures++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond || !detail ? "" : `   (${detail})`}`);
};

(async () => {
  const cfg = await import(path.join(ROOT, "seal-config.js"));
  const M = await globalThis.SealModule({ print() {}, printErr() {} });

  const signed = await cfg.buildSignedConfig(cfg.CFG_STANDARD);
  const ir = JSON.parse(M.ccall("seal_init", "string", ["string", "string"], [signed.envelope, signed.pubkey]));
  check("seal_init ok", ir.ok === true, JSON.stringify(ir));

  const decideLine = (line) => {
    const step = JSON.stringify({ line, now: 1000, approvals: [], votes: "", grants: "", forecasts: "" });
    return JSON.parse(M.ccall("seal_decide", "string", ["string"], [step]));
  };

  // (1) pathological number on a tools/call -> fail-closed block, never passthrough.
  const tc = decideLine(
    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute",` +
    `"arguments":{"database":"prod","sql":"drop table users","x":${PATHOLOGICAL}}}}`);
  check("pathological tools/call is BLOCKED (fail-closed)", tc.route === "block", JSON.stringify(tc));
  check("pathological tools/call is NEVER passthrough (the old d3067bc0 fail-open)",
    tc.route !== "passthrough", JSON.stringify(tc));
  check("verifier does not error/crash on the pathological line", !tc.error, tc.error || "");

  // (2) pathological number even on a would-be-passthrough line -> refused
  //     (the guard fires before the passthrough/act classification).
  const note = decideLine(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"x":${PATHOLOGICAL}}}`);
  check("pathological would-be-passthrough line is BLOCKED", note.route === "block", JSON.stringify(note));

  // (3) control: a benign line still passes through (no blanket block).
  const benign = decideLine(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"x":1}}`);
  check("control: benign line still passes through", benign.route === "passthrough", JSON.stringify(benign));

  console.log(failures === 0 ? "\nPATHOLOGICAL-NUMBER PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
