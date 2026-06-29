// SPDX-License-Identifier: Apache-2.0
// In-browser WASM evaluator adapter. Loads the compiled black-box seal kernel
// (wasm/seal.js, set up by a classic <script> tag as window.SealModule) and
// decides tool calls entirely in the browser — no backend.
import { SCENARIOS, CFG_STANDARD, buildEnvelope, buildStepInput, parseVerdict, PUBKEY } from "./seal-config.js";

let _mod = null;
async function mod() {
  if (_mod) return _mod;
  if (!window.SealModule) throw new Error("wasm/seal.js not loaded (need <script src=\"wasm/seal.js\">)");
  _mod = await window.SealModule({ print: () => {}, printErr: () => {} });
  return _mod;
}

// Load the session config, then decide one step. seal_init is cheap and resets
// kernel state, so each decision is self-contained and deterministic.
async function decideWith(config, step, tool) {
  const M = await mod();
  const ir = JSON.parse(M.ccall("seal_init", "string", ["string", "string"], [buildEnvelope(config), PUBKEY]));
  if (ir.ok !== true) throw new Error("seal_init failed: " + (ir.error || JSON.stringify(ir)));
  const raw = M.ccall("seal_decide", "string", ["string"], [step]);
  return parseVerdict(raw, tool);
}

// Decide a curated demo scenario by key (destructive-sql, wire-40k, pay-after, ...).
export async function decideScenario(key) {
  const s = SCENARIOS[key];
  if (!s) throw new Error("unknown scenario: " + key);
  return decideWith(s.config, buildStepInput(s), s.tool);
}

// Decide an audience-typed custom tool call (uses the rich standard config).
export async function decideCustom(tool, args, approvals = []) {
  return decideWith(CFG_STANDARD, buildStepInput({ tool, args, approvals }), tool);
}

// Decide an arbitrary trusted-config + tool call composed live by the presentation
// layer (the Policy Lab). seal_init accepts any trusted config, so this is a thin
// adapter over decideWith — no kernel logic. Reuses the WARM module singleton via
// mod(): the 617-module runtime instantiates once; each call does only the cheap
// seal_init(config) reset + seal_decide(step), so live re-decide has no cold re-init.
export async function decideConfig(config, { tool, args = {}, approvals = [], votes = "" }) {
  return decideWith(config, buildStepInput({ tool, args, approvals, votes }), tool);
}

// Decide an ORDERED sequence of calls in ONE session: seal_init once, then a seal_decide per step,
// so the kernel accumulates a REAL event trace across the steps (the stateful kernels — temporal,
// budget, linear — only fire on a sequence). Returns the verdict of the LAST step. Used to break
// the Temporal gate (a destructive db.execute after a session.revoke). `steps` = [{tool,args,approvals}].
export async function decideSeq(config, steps, tool) {
  const M = await mod();
  const ir = JSON.parse(M.ccall("seal_init", "string", ["string", "string"], [buildEnvelope(config), PUBKEY]));
  if (ir.ok !== true) throw new Error("seal_init failed: " + (ir.error || JSON.stringify(ir)));
  let raw;
  steps.forEach((s, i) => { raw = M.ccall("seal_decide", "string", ["string"], [buildStepInput({ ...s, id: i + 1 })]); });
  return parseVerdict(raw, tool);
}

// Warm the module (so first real decision is instant) and report readiness.
export async function ready() { await mod(); return true; }
