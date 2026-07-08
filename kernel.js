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
import { assembleReceiptV2, canonicalRequest, canonicalRequestSha256 } from "./receipt-format.js";

// --- pinned kernel identity (see AUDIT.md) ----------------------------------
// sha256 of wasm/seal.wasm, computed 2026-07-05. This is THE kernel id and the
// ONLY thing seal-check verifies in the browser. Toolchain + axioms below are
// LABELLED provenance the public Lean proofs assert — NOT verified here, NOT
// blended into the hash.
export const KERNEL_WASM_SHA256 = "ebd17c14668176612c49f6e2940b23df82a2c1a7cdef6759f0d6276ae997e9d0";
export const WASM_URL = "wasm/seal.wasm";
export const LEAN_TOOLCHAIN = "leanprover/lean4:v4.28.0";
export const KERNEL_AXIOMS = ["propext", "Classical.choice", "Quot.sound"];

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
// Pure-JS SHA-256 fallback. SubtleCrypto is only available in secure contexts
// (https, http://localhost, http://127.0.0.1) — a plain http://<hostname> origin
// does not get it. This fallback keeps the in-browser self-verification working on
// any http origin. Validated to match `sha256sum` on the pinned wasm.
export function sha256Hex(bytes) {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
      h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const l = bytes.length, bitLen = l * 8, withOne = l + 1;
  const k = (56 - (withOne % 64) + 64) % 64, total = withOne + k + 8;
  const m = new Uint8Array(total); m.set(bytes); m[l] = 0x80;
  const hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
  m[total - 8] = (hi >>> 24) & 255; m[total - 7] = (hi >>> 16) & 255; m[total - 6] = (hi >>> 8) & 255; m[total - 5] = hi & 255;
  m[total - 4] = (lo >>> 24) & 255; m[total - 3] = (lo >>> 16) & 255; m[total - 2] = (lo >>> 8) & 255; m[total - 1] = lo & 255;
  const w = new Uint32Array(64), rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let i = 0; i < total; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = (m[i + 4 * t] << 24) | (m[i + 4 * t + 1] << 16) | (m[i + 4 * t + 2] << 8) | (m[i + 4 * t + 3]);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[t] + w[t]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  const hx = (x) => (x >>> 0).toString(16).padStart(8, "0");
  return hx(h0) + hx(h1) + hx(h2) + hx(h3) + hx(h4) + hx(h5) + hx(h6) + hx(h7);
}

let _shaCache = null;
export async function verifyKernelSha() {
  if (_shaCache) return _shaCache;
  const buf = await (await fetch(WASM_URL)).arrayBuffer();
  let computed, method;
  if (crypto && crypto.subtle) {
    const digest = await crypto.subtle.digest("SHA-256", buf);
    computed = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
    method = "SubtleCrypto";
  } else {
    computed = sha256Hex(new Uint8Array(buf)); // non-secure origin (e.g. http://hostname)
    method = "js-fallback";
  }
  // method is intentionally NOT part of the receipt — the hash is identical either way.
  _shaCache = { computed, pinned: KERNEL_WASM_SHA256, match: computed === KERNEL_WASM_SHA256, method };
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

// --- receipt (schema v2, two strictly-separate, labelled blocks) -------------
// Emits the canonical v2 decision receipt (normative spec:
// docs/DECISION-RECEIPT-SCHEMA.md §11) via the shared receipt-format.js
// seam. kernel_identity = binary fact, self-verified (HARD SPLIT — never
// carries toolchain/axioms). asserted_provenance = proof hygiene the Lean
// sources claim, NOT verified here and NOT part of the hash. The hash must
// never read as proving the axioms.
//
// `call` = { tool, args, approvals, now } — the SAME decision inputs fed to
// the kernel. seal-check's approvals are raw 64-hex targets (the fire-your-own
// box accepts arbitrary target commitments), so grants are carried as OPAQUE
// { target } entries per spec §3: the pre-image is not held here, and the
// receipt says so instead of inventing one. The same honesty rule shapes the
// v2 approval block: targets pasted by a human into this page are an
// "interactive" channel approval with no nonce/issued_at/expiry to assert;
// args_hash and approval.policy_hash are derived inside the seam.
export function buildReceipt({ call, config, parsed, raw, sha }) {
  const verdict = parsed.verdict === "DENY" ? "BLOCK" : parsed.verdict; // ALLOW | BLOCK | ERROR
  return assembleReceiptV2({
    tool: call.tool,
    arguments: call.args,
    now: call.now ?? 1000,
    canonical_request: canonicalRequest(call.tool, call.args),
    canonical_request_sha256: canonicalRequestSha256(call.tool, call.args),
    bypass: false,
    verdict,
    approval: verdict === "ALLOW"
      ? { approval_identity: { channel: "interactive" } } // policy_hash derived in the seam
      : undefined,
    reason: parsed.reason,
    deny_kernel: parsed.deny_kernel ?? null,
    certs: parsed.certs, // per-gate seals (FNV-1a 64-bit certHashes, decimal strings)
    emitted_bytes: raw, // verbatim canonical seal_decide output — the decision bytes
    kernel_identity: {
      wasm_sha256: sha.computed,
      self_verified: sha.match,
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
    kernel_config: config,
    granted_capabilities: (call.approvals || []).map((t) => ({ target: String(t) })),
  });
}

// Deterministic serialization: object key order is fixed by construction above,
// so JSON.stringify is byte-stable. Same input → identical bytes, every reload.
export function canonicalReceiptJson(receipt) {
  return JSON.stringify(receipt, null, 2) + "\n";
}
