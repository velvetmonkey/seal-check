// SPDX-License-Identifier: Apache-2.0
// receipt-format.js — the ONE shared implementation of the canonical decision-
// receipt format (normative spec: docs/DECISION-RECEIPT-SCHEMA.md).
//
// CANONICAL SOURCE. seal-assurance-kit vendors a byte-identical copy at
// kernel/receipt-format.js (same discipline as its vendored kernel.js /
// seal-config.js): any change lands HERE first, then is re-copied verbatim.
//
// Pure ES module, browser + Node, zero dependencies. This module is the
// serialization/format seam ONLY — no kernel logic, no decision semantics.
// Day-1 freeze: these exports are the contract producers/verifiers converge
// on; signatures do not change without a spec bump.

export const RECEIPT_SCHEMA_VERSION = "v1";
export const RECEIPT_SCHEMA_VERSION_V2 = "v2";
export const RECEIPT_VERSION_KEY = "seal_receipt";
export const LEGACY_VERSION_KEYS = ["seal_live_receipt", "seal_check_receipt"];
export const VERDICTS = ["ALLOW", "BLOCK", "ERROR"];
export const APPROVAL_CHANNELS = ["file", "interactive", "ed25519"];
// Host audit lines (seal-host/Host/Audit.lean) speak lowercase; receipts never do.
export const HOST_AUDIT_VERDICT_MAP = { allow: "ALLOW", deny: "BLOCK" };

// --- §2: canonical request line + hash --------------------------------------
// The single pre-image both prior dialects converge on. `args` is serialized
// in its stored key order (integer-like argument names are forbidden in v1).
export function canonicalRequest(tool, args, id = 1) {
  return JSON.stringify({
    jsonrpc: "2.0", id, method: "tools/call",
    params: { name: tool, arguments: args },
  });
}

// Pure-JS SHA-256 (identical algorithm to seal-check/kernel.js sha256Hex,
// validated against `sha256sum`). Sync + dependency-free so the SAME bytes
// hash the SAME way in the browser, in Node, and in any vendored copy.
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

export function canonicalRequestSha256(tool, args) {
  return sha256Hex(new TextEncoder().encode(canonicalRequest(tool, args)));
}

// --- §11.3: derived hashes ---------------------------------------------------
// SHA-256 over the UTF-8 bytes of JSON.stringify(obj) in the object's stored
// key order — the §2 serialization discipline. v2 uses this for args_hash
// (over `arguments`) and approval.policy_hash (over `kernel_config`).
// Verifiers recompute both and reject on mismatch.
export function canonicalJsonSha256(obj) {
  return sha256Hex(new TextEncoder().encode(JSON.stringify(obj)));
}

// §11.4: a tool's payment-class declaration from the runtime config (never
// proof-bearing). Returns {class, bind: {amount, merchant, currency}} or null.
export function paymentDeclFor(kernelConfig, tool) {
  const tools = (kernelConfig && kernelConfig.safety && kernelConfig.safety.tools) || [];
  const spec = tools.find((t) => t.name === tool);
  return spec && spec.payment && spec.payment.class === "payment" && isObj(spec.payment.bind)
    ? spec.payment : null;
}

// --- §3: capability targets --------------------------------------------------
// Exact mirror of Lean Seal.stableHashParts: SHA-256 over the injective
// netstring encoding used by Seal.encodeParts.
export function encodeParts(parts) {
  return parts.map((s) => {
    const p = String(s);
    return `${[...p].length}:${p}`;
  }).join("");
}

export function stableHashParts(parts) {
  return sha256Hex(new TextEncoder().encode(encodeParts(parts)));
}

// THE pinned convention: target = stableHashParts([tool, ...parts]) where
// `parts` are the policy target-spec entries resolved in policy order.
// Arity is policy-determined; the convention is not.
export function capabilityTarget(tool, parts) {
  return stableHashParts([tool, ...parts]);
}

// §3 verifier recompute: resolve each granted_capabilities entry to its
// approval target. Un-hashed entries ({tool, ...fields}) are recomputed from
// the policy's target spec — {literal} parts come from the POLICY, {arg}
// parts from the ENTRY's field of that name. Opaque entries ({target}) are
// grants whose pre-image the producer did not hold; their 64-hex target is
// used verbatim (the verifier can re-derive the verdict but cannot check the
// grant binding — flagged via `opaque`). Returns
// { approvals: string[], opaque: number, errors: string[] }.
export function capabilityTargetsFromPolicy(kernelConfig, grants) {
  const approvals = [], errors = [];
  let opaque = 0;
  const tools = (kernelConfig && kernelConfig.safety && kernelConfig.safety.tools) || [];
  for (const g of grants || []) {
    if (g && typeof g.target === "string" && HEX64.test(g.target)) {
      approvals.push(g.target); opaque++; continue;
    }
    if (!g || typeof g.tool !== "string") { errors.push("grant entry: need .tool or .target"); continue; }
    const spec = tools.find((t) => t.name === g.tool);
    if (!spec || !Array.isArray(spec.target)) {
      errors.push(`grant entry for ${g.tool}: no policy target spec in kernel_config`); continue;
    }
    let bad = null;
    const parts = spec.target.map((p) => {
      if (typeof p.literal === "string") return p.literal;
      if (typeof p.arg === "string") {
        if (!(p.arg in g)) bad = `grant entry for ${g.tool}: missing field ${p.arg}`;
        return String(g[p.arg]);
      }
      bad = `grant entry for ${g.tool}: unrecognized target-spec part`;
      return "";
    });
    if (bad) { errors.push(bad); continue; }
    approvals.push(capabilityTarget(g.tool, parts));
  }
  return { approvals, opaque, errors };
}

// §1 canonical assembly: fixed top-level key order so every v1 producer is
// byte-stable under JSON.stringify (the determinism checks rely on it).
// Undefined fields are omitted; `bypass` and required fields are the
// caller's responsibility (validateReceipt enforces them).
const V1_KEY_ORDER = [
  "seal_receipt", "tool", "arguments", "now", "canonical_request",
  "canonical_request_sha256", "bypass", "verdict", "reason", "deny_kernel",
  "certs", "emitted_bytes", "kernel_identity", "asserted_provenance",
  "kernel_config", "granted_capabilities", "policy_id", "signature",
];
export function assembleReceiptV1(fields) {
  const r = { seal_receipt: RECEIPT_SCHEMA_VERSION };
  for (const k of V1_KEY_ORDER) {
    if (k === "seal_receipt") continue;
    if (fields[k] !== undefined) r[k] = fields[k];
  }
  return r;
}

// §11.5 canonical v2 assembly. Same discipline as V1 plus the v2 fields, with
// the approval block's sub-object key order fixed too. Derived hashes are
// computed HERE from the receipt's own arguments/kernel_config (single source;
// producers cannot skew them), unless the receipt is a bypass.
const V2_KEY_ORDER = [
  "seal_receipt", "tool", "action", "arguments", "args_hash", "now",
  "canonical_request", "canonical_request_sha256", "bypass", "verdict",
  "reason", "deny_kernel", "amount", "merchant", "currency", "approval",
  "certs", "emitted_bytes", "kernel_identity", "asserted_provenance",
  "kernel_config", "granted_capabilities", "policy_id", "signature",
];
const APPROVAL_KEY_ORDER = ["approval_identity", "nonce", "issued_at", "expiry", "policy_hash"];
const IDENTITY_KEY_ORDER = ["channel", "key_id"];

function orderKeys(obj, order) {
  const out = {};
  for (const k of order) if (obj[k] !== undefined) out[k] = obj[k];
  return out;
}

export function assembleReceiptV2(fields) {
  const f = { ...fields };
  if (f.bypass === false && isObj(f.arguments) && f.args_hash === undefined) {
    f.args_hash = canonicalJsonSha256(f.arguments);
  }
  if (isObj(f.approval)) {
    const a = { ...f.approval };
    if (a.policy_hash === undefined && isObj(f.kernel_config)) {
      a.policy_hash = canonicalJsonSha256(f.kernel_config);
    }
    if (isObj(a.approval_identity)) a.approval_identity = orderKeys(a.approval_identity, IDENTITY_KEY_ORDER);
    f.approval = orderKeys(a, APPROVAL_KEY_ORDER);
  }
  const r = { seal_receipt: RECEIPT_SCHEMA_VERSION_V2 };
  for (const k of V2_KEY_ORDER) {
    if (k === "seal_receipt") continue;
    if (f[k] !== undefined) r[k] = f[k];
  }
  return r;
}

// --- §1/§7: shape validation ---------------------------------------------------
const HEX64 = /^[0-9a-f]{64}$/;
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// Structural validation against the v1/v2 field tables. Returns
// { ok, version, errors }. version: "v2" (current) | "v1" (accepted-legacy) |
// "v0-live" (grandfathered) | "v0-check" (rejected legacy Schema K) |
// null (unrecognized).
export function validateReceipt(r) {
  const errors = [];
  if (!isObj(r)) return { ok: false, version: null, errors: ["receipt is not an object"] };

  let version = null;
  if (r.seal_receipt === RECEIPT_SCHEMA_VERSION_V2) version = "v2";
  else if (r.seal_receipt === RECEIPT_SCHEMA_VERSION) version = "v1";
  else if (r.seal_live_receipt === "v0") version = "v0-live";
  else if ("seal_check_receipt" in r) {
    return { ok: false, version: "v0-check",
      errors: ["legacy Schema K (seal_check_receipt) — not v1-compatible; regenerate with a v1 producer (see docs/DECISION-RECEIPT-SCHEMA.md)"] };
  } else {
    return { ok: false, version: null, errors: ["no recognized version discriminator"] };
  }

  if (typeof r.tool !== "string" || !r.tool) errors.push("tool: non-empty string required");
  if (!isObj(r.arguments)) errors.push("arguments: object required");
  if (typeof r.canonical_request_sha256 !== "string" || !HEX64.test(r.canonical_request_sha256))
    errors.push("canonical_request_sha256: 64-hex string required");
  if (typeof r.bypass !== "boolean") errors.push("bypass: boolean required");
  if (!VERDICTS.includes(r.verdict)) errors.push(`verdict: one of ${VERDICTS.join("|")} required`);
  if (typeof r.reason !== "string") errors.push("reason: string required");
  if (!isObj(r.kernel_identity)) errors.push("kernel_identity: object required");

  // §2: if the pre-image line is stored, it must be the derived one.
  if (typeof r.tool === "string" && isObj(r.arguments) && typeof r.canonical_request === "string" &&
      r.canonical_request !== canonicalRequest(r.tool, r.arguments))
    errors.push("canonical_request: does not equal the line derived from (tool, arguments)");

  if (isObj(r.kernel_identity)) {
    const w = r.kernel_identity.wasm_sha256;
    if (r.bypass === true) {
      if (w !== null) errors.push("kernel_identity.wasm_sha256: must be null on bypass");
    } else if (typeof w !== "string" || !HEX64.test(w)) {
      errors.push("kernel_identity.wasm_sha256: 64-hex string required when mediated");
    }
    // §4 HARD SPLIT (v1 and v2; v0-live merged blocks are grandfathered):
    // identity is the binary hash — asserted provenance lives in its own
    // block. A v1/v2 kernel_identity carrying toolchain/axioms is INVALID.
    if (version === "v1" || version === "v2") {
      for (const k of ["lean_toolchain", "axioms"]) {
        if (k in r.kernel_identity)
          errors.push(`kernel_identity.${k}: forbidden in ${version} (hard split, L0 §6.2) — move to asserted_provenance`);
      }
      if (typeof r.kernel_identity.self_verified !== "boolean")
        errors.push(`kernel_identity.self_verified: boolean required in ${version}`);
    }
  }
  if ((version === "v1" || version === "v2") && "asserted_provenance" in r) {
    if (!isObj(r.asserted_provenance) || r.asserted_provenance.verified_in_browser === true)
      errors.push("asserted_provenance: object with verified_in_browser !== true required (asserted, never verified)");
  }
  if ("now" in r && (!Number.isInteger(r.now) || r.now < 0))
    errors.push("now: non-negative integer when present");

  if (r.bypass === false) {
    if (!isObj(r.kernel_config)) errors.push("kernel_config: object required when mediated");
    if (!Array.isArray(r.certs)) errors.push("certs: array required when mediated");
    if (typeof r.emitted_bytes !== "string") errors.push("emitted_bytes: string required when mediated");
    if (!Array.isArray(r.granted_capabilities) ||
        !r.granted_capabilities.every((g) => isObj(g) &&
          (typeof g.tool === "string" || (typeof g.target === "string" && HEX64.test(g.target)))))
      errors.push("granted_capabilities: array of {tool,...} or opaque {target} entries required when mediated");
    if (!("deny_kernel" in r)) errors.push("deny_kernel: required when mediated (string or null)");
  }

  if (version === "v2") validateV2Extras(r, errors);

  return { ok: errors.length === 0, version, errors };
}

// §11 checks beyond the shared v1 core. Derived hashes are RECOMPUTED here —
// a receipt asserting a hash its own fields do not produce is invalid.
function validateV2Extras(r, errors) {
  if ("action" in r && (typeof r.action !== "string" || !r.action))
    errors.push("action: non-empty string when present");

  if (r.bypass === false) {
    if (typeof r.args_hash !== "string" || !HEX64.test(r.args_hash))
      errors.push("args_hash: 64-hex string required when mediated (v2)");
    else if (isObj(r.arguments) && r.args_hash !== canonicalJsonSha256(r.arguments))
      errors.push("args_hash: does not equal sha256 of the canonical arguments serialization");
  } else if ("args_hash" in r) {
    errors.push("args_hash: must be absent on bypass");
  }

  // Approval block: required on mediated ALLOW; optional on BLOCK; forbidden on bypass.
  if (r.bypass === true && "approval" in r) errors.push("approval: must be absent on bypass");
  if (r.bypass === false && r.verdict === "ALLOW" && !isObj(r.approval))
    errors.push("approval: object required on mediated ALLOW (v2)");
  if (isObj(r.approval)) {
    const a = r.approval;
    const id = a.approval_identity;
    if (!isObj(id)) errors.push("approval.approval_identity: object required");
    else {
      if (!APPROVAL_CHANNELS.includes(id.channel))
        errors.push(`approval.approval_identity.channel: one of ${APPROVAL_CHANNELS.join("|")} required`);
      if (id.channel === "ed25519") {
        if (typeof id.key_id !== "string" || !id.key_id)
          errors.push("approval.approval_identity.key_id: required on the ed25519 channel");
      } else if ("key_id" in id) {
        errors.push("approval.approval_identity.key_id: only the ed25519 channel carries a key_id");
      }
    }
    if (typeof a.policy_hash !== "string" || !HEX64.test(a.policy_hash))
      errors.push("approval.policy_hash: 64-hex string required");
    else if (isObj(r.kernel_config) && a.policy_hash !== canonicalJsonSha256(r.kernel_config))
      errors.push("approval.policy_hash: does not equal sha256 of the canonical kernel_config serialization");
    for (const k of ["issued_at", "expiry"]) {
      if (k in a && (!Number.isInteger(a[k]) || a[k] < 0))
        errors.push(`approval.${k}: non-negative integer (epoch ms) when present`);
    }
    if ("nonce" in a && (typeof a.nonce !== "string" || !a.nonce))
      errors.push("approval.nonce: non-empty string when present");
    if (isObj(id) && id.channel === "ed25519") {
      for (const k of ["nonce", "issued_at", "expiry"]) {
        if (!(k in a)) errors.push(`approval.${k}: required on the ed25519 channel`);
      }
    }
  }

  // §11.4 payment class: fields present iff the runtime config declares the
  // class, and each byte-equals its bound argument. Fabrication is invalid.
  const decl = isObj(r.kernel_config) ? paymentDeclFor(r.kernel_config, r.tool) : null;
  const PAYMENT_FIELDS = ["amount", "merchant", "currency"];
  if (decl) {
    for (const f of PAYMENT_FIELDS) {
      const argName = decl.bind[f];
      if (!(f in r)) { errors.push(`${f}: required for payment-class tool ${r.tool}`); continue; }
      if (typeof argName !== "string" || !isObj(r.arguments) || !(argName in r.arguments)) {
        errors.push(`${f}: payment binding names argument ${JSON.stringify(argName)} which is not present`);
      } else if (r[f] !== r.arguments[argName]) {
        errors.push(`${f}: does not equal bound argument ${argName} (verbatim copy required)`);
      }
    }
  } else {
    for (const f of PAYMENT_FIELDS) {
      if (f in r) errors.push(`${f}: present but the config declares no payment class for ${r.tool} (fabrication)`);
    }
  }
}
