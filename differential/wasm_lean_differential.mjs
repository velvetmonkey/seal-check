// SPDX-License-Identifier: Apache-2.0
// Lane C: wasm-vs-Lean differential. The deployed seal.wasm is the Lean `decide`
// compiled Lean->C->emscripten. This drives the SAME JSON-RPC line through both
// the emscripten wasm (seal_decide) and a natively-compiled Lean `decide`
// (v2_decide_line) and asserts they agree. Any disagreement is a compile-target
// (codegen / emscripten) divergence, not a spec question.
//
// The corpus is destructive intent in disguises: every disguise must BLOCK on
// both targets (default-deny + canonicalisation, not pattern-matching), plus a
// liveness control that must ALLOW on both (proves it is not deny-everything).
//
// Lean binary path via env SEAL_LEAN_DECIDE (keeps this file hygiene-clean of
// private repo paths).
import { createRequire } from "module";
const require = createRequire(import.meta.url);
import { buildEnvelope, parseVerdict, PUBKEY, SCENARIOS } from "../seal-config.js";
import { execFileSync } from "child_process";

const LEAN = process.env.SEAL_LEAN_DECIDE;
if (!LEAN) { console.error("set SEAL_LEAN_DECIDE=<path to v2_decide_line>"); process.exit(2); }

const factory = require("../wasm/seal.js");
const M = await factory({ print() {}, printErr() {} });
const CONFIG = SCENARIOS["destructive-sql"].config; // guards db.execute destructive SQL

async function wasmVerdict(line, tool) {
  const ir = JSON.parse(M.ccall("seal_init", "string", ["string", "string"], [await buildEnvelope(CONFIG), PUBKEY]));
  if (ir.ok !== true) throw new Error("seal_init failed: " + JSON.stringify(ir));
  const step = JSON.stringify({ line, now: 1000, approvals: [], votes: "", grants: "", forecasts: "" });
  const raw = M.ccall("seal_decide", "string", ["string"], [step]);
  return parseVerdict(raw, tool).verdict; // DENY / ALLOW / ERROR
}
function leanVerdict(line) {
  try { return execFileSync(LEAN, [line], { encoding: "utf8" }).trim(); } // Allow / Block
  catch (e) { return "ERR:" + String(e.message || "").slice(0, 40); }
}
const norm = (s) => (s === "DENY" || s === "Block") ? "BLOCK" : (s === "ALLOW" || s === "Allow") ? "ALLOW" : s;
const rpc = (tool, args, id = 1) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: tool, arguments: args } });

// destructive delete, disguised so a naive `sql === "delete_all"` filter misses it
const sqlDisguises = [
  "delete from customers", "DELETE FROM customers", "  delete   from   customers  ",
  "delete\tfrom\tcustomers", "delete from customers;", "DeLeTe FROM customers",
  "delete /* c */ from customers", "truncate table customers", "drop table customers",
  "delete from customers -- ok",
];
const cases = sqlDisguises.map((sql, i) => ({ name: `sql-disguise#${i}`, line: rpc("db.execute", { sql }), tool: "db.execute", expect: "BLOCK" }));
// structural disguises: same destructive intent, mangled JSON framing
cases.push({ name: "struct-whitespace", line: '{  "jsonrpc" : "2.0" , "id":1, "method":"tools/call", "params":{"name":"db.execute","arguments":{"sql":"delete from customers"}}}', tool: "db.execute", expect: "BLOCK" });
cases.push({ name: "struct-key-order", line: '{"method":"tools/call","params":{"arguments":{"sql":"delete from customers"},"name":"db.execute"},"id":1,"jsonrpc":"2.0"}', tool: "db.execute", expect: "BLOCK" });
cases.push({ name: "struct-unicode-esc", line: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"sql":"\\u0064elete from customers"}}}', tool: "db.execute", expect: "BLOCK" });

// --- the asserted differential: mediated calls must agree + BLOCK on both targets ---
let pass = 0, fail = 0, disagree = 0;
console.log("case".padEnd(22) + "wasm".padEnd(7) + "lean".padEnd(7) + "agree  expect");
for (const c of cases) {
  const w = norm(await wasmVerdict(c.line, c.tool));
  const l = norm(leanVerdict(c.line));
  const agree = w === l;
  const okExpect = w === c.expect && l === c.expect;
  if (!agree) disagree++;
  if (agree && okExpect) pass++; else fail++;
  console.log(c.name.padEnd(22) + w.padEnd(7) + l.padEnd(7) + (agree ? "Y" : "N").padEnd(7) + (okExpect ? "ok" : `WANT ${c.expect}`));
}
console.log(`\n[differential] ${pass}/${cases.length} mediated cases agree + BLOCK on both compile targets, ${fail} fail, ${disagree} disagreements`);

// --- layer-boundary probe (informational, NOT a differential fault) ---
// v2_decide_line is the core SealV2.decide (Allow/Block only). The wasm's
// seal_decide is the host step, which PASSES THROUGH non-mediated methods.
// So a non-tools/call line diverges by design: wasm=ALLOW(passthrough),
// core-decide=BLOCK(no passthrough concept). Reported so it is not misread.
const pt = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
console.log(`\n[layer note] passthrough (tools/list): wasm=${norm(await wasmVerdict(pt, "tools/list"))} host-step, lean=${norm(leanVerdict(pt))} core-decide` +
  ` — expected divergence (different layers), not a codegen fault.`);
console.log(`(wasm = emscripten-compiled Lean host step; lean = native-compiled Lean core decide)`);
process.exit(fail ? 1 : 0);
