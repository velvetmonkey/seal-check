// SPDX-License-Identifier: Apache-2.0
// seal-check kernel glue — the ONLY new logic in seal-check.
//
// Loads the compiled black-box seal kernel (wasm/seal.js installs window.SealModule),
// runs a decision, and captures the CANONICAL EMITTED BYTES (the verbatim seal_decide
// output) that the upstream seal-wasm.js adapter discards after parsing. seal-check
// needs those bytes for the reproducible receipt.
//
// There is NO kernel logic here: this file only loads the module, calls the two
// exported symbols (seal_init / seal_decide), hashes the binary, and wraps the result.
// All decision semantics live inside the compiled wasm; all input/output shaping is
// reused verbatim from seal-config.js.
import { buildEnvelope, buildStepInput, parseVerdict, PUBKEY } from "./seal-config.js";

// --- pinned kernel identity (see AUDIT.md) ----------------------------------
// sha256 of wasm/seal.wasm, computed 2026-06-29. This is THE kernel id and the
// ONLY thing seal-check verifies in the browser. Toolchain + axioms below are
// LABELLED provenance the public Lean proofs assert — NOT verified here, NOT
// blended into the hash.
export const KERNEL_WASM_SHA256 = "1cc765c7de2cead88eda2e8e5f5af5a5e070f35a767916e754b873733562c70a";
export const WASM_URL = "wasm/seal.wasm";
export const LEAN_TOOLCHAIN = "leanprover/lean4:v4.28.0";
export const KERNEL_AXIOMS = ["propext", "Classical.choice", "Quot.sound"];
export const RECEIPT_VERSION = "v0";

// --- module singleton (one wasm instance for the whole page) ----------------
let _mod = null;
async function mod() {
  if (_mod) return _mod;
  if (!window.SealModule) {
    throw new Error('wasm/seal.js not loaded (need <script src="wasm/seal.js"> before this module)');
  }
  _mod = await window.SealModule({ print: () => {}, printErr: () => {} });
  return _mod;
}
export async function ready() { await mod(); return true; }

// --- kernel binary self-verification (the ONLY in-browser verification) -----
// Fetch the wasm bytes, SHA-256 them with SubtleCrypto, compare to the pinned
// constant. Returns {computed, pinned, match}. Requires a secure context;
// http://localhost and 127.0.0.1 qualify, so `python3 -m http.server` is fine.
let _shaCache = null;
export async function verifyKernelSha() {
  if (_shaCache) return _shaCache;
  if (!(crypto && crypto.subtle)) {
    throw new Error("SubtleCrypto unavailable — serve over http://localhost (not file://)");
  }
  const buf = await (await fetch(WASM_URL)).arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  const computed = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  _shaCache = { computed, pinned: KERNEL_WASM_SHA256, match: computed === KERNEL_WASM_SHA256 };
  return _shaCache;
}

// --- decide, capturing the raw emitted bytes --------------------------------
// Single self-contained decision (seal_init resets state, then one seal_decide).
export async function decideRaw(config, { tool, args = {}, approvals = [], now = 1000, votes = "" }) {
  const M = await mod();
  const ir = JSON.parse(M.ccall("seal_init", "string", ["string", "string"], [buildEnvelope(config), PUBKEY]));
  if (ir.ok !== true) throw new Error("seal_init failed: " + (ir.error || JSON.stringify(ir)));
  const step = buildStepInput({ tool, args, approvals, now, votes });
  const raw = M.ccall("seal_decide", "string", ["string"], [step]);
  return { raw, step, parsed: parseVerdict(raw, tool) };
}

// Ordered multi-step session in ONE init (the stateful kernels — temporal,
// budget, linear — only fire across a trace). Returns the LAST step's result.
// `steps` = [{tool, args, approvals?, now?}].
export async function decideSeqRaw(config, steps, tool) {
  const M = await mod();
  const ir = JSON.parse(M.ccall("seal_init", "string", ["string", "string"], [buildEnvelope(config), PUBKEY]));
  if (ir.ok !== true) throw new Error("seal_init failed: " + (ir.error || JSON.stringify(ir)));
  let raw, step;
  steps.forEach((s, i) => {
    step = buildStepInput({ ...s, id: i + 1 });
    raw = M.ccall("seal_decide", "string", ["string"], [step]);
  });
  return { raw, step, parsed: parseVerdict(raw, tool) };
}

// --- receipt (two strictly-separate, labelled blocks) -----------------------
// kernel_identity = binary fact, self-verified. asserted_provenance = proof
// hygiene the Lean sources claim, NOT verified here and NOT part of the hash.
// The hash must never read as proving the axioms.
export function buildReceipt({ input, parsed, raw, sha }) {
  return {
    seal_check_receipt: RECEIPT_VERSION,
    input,
    verdict: parsed.verdict === "DENY" ? "BLOCK" : parsed.verdict, // ALLOW | BLOCK | ERROR
    reason: parsed.reason,
    deny_kernel: parsed.deny_kernel ?? null,
    emitted_bytes: raw, // verbatim canonical seal_decide output — the decision bytes
    witness: { certs: parsed.certs }, // per-gate seals (FNV-1a 64-bit certHashes)
    kernel_identity: {
      wasm_sha256: sha.computed,
      self_verified_in_browser: sha.match,
      note:
        "Binary identity of the evaluator actually executed. Hashed in your browser " +
        "from the loaded bytes and compared to a pinned constant. This is the ONLY " +
        "thing verified here.",
    },
    asserted_provenance: {
      verified_in_browser: false,
      lean_toolchain: LEAN_TOOLCHAIN,
      axioms: KERNEL_AXIOMS,
      note:
        "What the public Lean proofs ASSERT about the kernel source. NOT verified in " +
        "your browser and NOT part of the hash above.",
    },
  };
}

// Deterministic serialization: object key order is fixed by construction above,
// so JSON.stringify is byte-stable. Same input → identical bytes, every reload.
export function canonicalReceiptJson(receipt) {
  return JSON.stringify(receipt, null, 2) + "\n";
}
