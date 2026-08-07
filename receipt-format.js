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
// §12 (v3) vocabularies. RELEASE_STATUSES is SCREAMING_SNAKE on the wire
// (host ReleaseStatus); DURABILITY_CLASSES is the READABLE set — the v1 host
// emitter can only produce asserted_local_fsync|unknown, but a verifier must
// accept (and a future witness protocol may emit) witnessed_external.
export const RELEASE_STATUSES = ["PENDING", "UNKNOWN", "RELEASED", "NOT_APPLICABLE"];
export const DURABILITY_CLASSES = ["asserted_local_fsync", "witnessed_external", "unknown"];
// §12.2 Object B signature domain. The wire `signature.domain` field carries
// this 16-char name; the signing preimage appends one 0x00 (17 bytes total).
// NOT the v1 optional live-demo HMAC `signature`, NOT `signed_config`.
export const RECEIPT_SIGNATURE_DOMAIN = "seal.object-b/v1";
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

// Exact mirror of Lean Json.compress for the JSON values admitted as tool
// arguments: object keys are ordered lexicographically at every depth.
function canonicalCompact(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalCompact).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalCompact(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

// Stage-A guarded target. Metadata, request state and input responses are
// absent on the receipt replay path and therefore contribute explicit frames.
export function guardTarget(kernelConfig, tool, canonicalParts) {
  const server = kernelConfig?.server || kernelConfig?.safety?.server || "";
  return stableHashParts([
    "seal.guard-target/v2-proposed-meta-all",
    ...(server === "" ? [tool] : [server, tool]),
    ...canonicalParts,
    "meta.absent", "", "requestState.absent", "",
    "inputResponses.absent", "",
  ]);
}

// §3 verifier recompute: resolve each granted_capabilities entry to its
// approval target. Un-hashed entries ({tool, ...fields}) are recomputed from
// the policy's target spec — {literal} parts come from the POLICY, {arg}
// parts from the ENTRY's field of that name, and {full_arguments:true} binds
// the ENTRY's complete canonical .arguments object. Opaque entries ({target}) are
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
      if (p.full_arguments === true) {
        if (!("arguments" in g)) bad = `grant entry for ${g.tool}: missing field arguments`;
        return canonicalCompact(g.arguments);
      }
      bad = `grant entry for ${g.tool}: unrecognized target-spec part`;
      return "";
    });
    if (bad) { errors.push(bad); continue; }
    approvals.push(spec.target.some((p) => p.full_arguments === true)
      ? guardTarget(kernelConfig, g.tool, parts)
      : capabilityTarget(g.tool, parts));
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
  "canonical_request", "canonical_request_sha256", "request_sha256", "request_parse_error",
  "bypass", "verdict",
  "authorization", "reason", "deny_kernel", "amount", "merchant", "currency", "approval",
  "certs", "emitted_bytes", "kernel_identity", "host_identity", "asserted_provenance",
  "signed_config", "kernel_config", "granted_capabilities", "policy_id", "signature",
];
const APPROVAL_KEY_ORDER = ["approval_identity", "nonce", "issued_at", "expiry", "policy_hash"];
const IDENTITY_KEY_ORDER = ["channel", "key_id"];
const SIGNED_CONFIG_KEY_ORDER = ["payload", "signature", "pubkey"];

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
  if (isObj(f.signed_config)) f.signed_config = orderKeys(f.signed_config, SIGNED_CONFIG_KEY_ORDER);
  const r = { seal_receipt: RECEIPT_SCHEMA_VERSION_V2 };
  for (const k of V2_KEY_ORDER) {
    if (k === "seal_receipt") continue;
    if (f[k] !== undefined) r[k] = f[k];
  }
  return r;
}

// --- §1/§7: shape validation ---------------------------------------------------
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// --- §12.6: the received DOCUMENT, not only the parsed object ------------------
// A receipt is a byte string somebody signed. `JSON.parse` is LOSSY about that
// byte string: a repeated member collapses to its last occurrence, `3.0` and
// `3` fold to the same double, and `"record_version"` and
// `"record_version"` become the same key. Validating only the parsed object
// therefore lets an attacker choose which of two documents we believe we
// received: a real signed v3 record whose TEXT carries both
// `"record_version": 3` and `"record_version": 2` parses to a v2 object,
// classifies as v2, never runs the Object B signature check, and comes back
// `ok: true` — with no conflicting families for the §12.0 rule to see, because
// after the parse the object genuinely claims one version. The lie is in the
// bytes, so the bytes are what has to be checked.
//
// The five key names that decide which schema (and therefore which crypto) a
// record is judged under. Repetition or an escaped spelling of ANY of these in
// the received text is fatal.
export const DISCRIMINATOR_KEYS = [
  "seal_receipt", "record_type", "record_version", "seal_live_receipt", "seal_check_receipt",
];

// A structure-aware JSON reader. NOT a regex over the text: a string that
// looks like `"record_version"` can legitimately appear inside a VALUE (a
// reason string, an emitted_bytes blob), and counting textual occurrences
// would refuse honest receipts. This walks the grammar and reports only what
// is genuinely a member NAME of the top-level object. It builds no values —
// the authoritative parse is still `JSON.parse` on the same untouched bytes;
// nothing here canonicalises, re-serialises, or otherwise disturbs the
// preimage the signature covers.
//
// One honest divergence from `JSON.parse`, and it fails CLOSED: the reader
// recurses, so a document nested deeper than roughly 10^4 levels exhausts the
// JS stack and is refused as not-well-formed where `JSON.parse` (iterative)
// would accept it. Real receipts nest ~5 deep.
const JSON_ESCAPES = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
const CANONICAL_UINT = /^(0|[1-9][0-9]*)$/;

// Returns { ok, errors, topLevel } where topLevel is a Map of decoded member
// name -> { count, escaped, numberLiterals }, or null when the document's root
// is not an object. Structural failures are reported, never thrown.
export function scanReceiptDocument(text) {
  const errors = [];
  if (typeof text !== "string")
    return { ok: false, errors: ["document: raw receipt text (a string) required"], topLevel: null };
  if (text.charCodeAt(0) === 0xfeff)
    return { ok: false, errors: ["document: begins with a byte-order mark — a BOM is not JSON and must not be stripped by a verifier (fail closed, §12.6)"], topLevel: null };

  let i = 0;
  let topLevel = null;
  const fail = (msg) => { throw new SyntaxError(`${msg} at offset ${i}`); };
  const ws = () => {
    while (i < text.length) {
      const c = text[i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") i++;
      else break;
    }
  };
  const readString = () => {
    if (text[i] !== '"') fail("expected a string");
    i++;
    let value = "", escaped = false;
    for (;;) {
      if (i >= text.length) fail("unterminated string");
      const c = text[i];
      if (c === '"') { i++; return { value, escaped }; }
      if (c === "\\") {
        escaped = true;
        i++;
        const e = text[i++];
        if (e === "u") {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("invalid \\u escape");
          value += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else if (Object.prototype.hasOwnProperty.call(JSON_ESCAPES, e)) {
          value += JSON_ESCAPES[e];
        } else fail("invalid escape");
        continue;
      }
      if (c.charCodeAt(0) < 0x20) fail("unescaped control character in string");
      value += c;
      i++;
    }
  };
  const readNumber = () => {
    const start = i;
    if (text[i] === "-") i++;
    if (text[i] === "0") i++;
    else if (text[i] >= "1" && text[i] <= "9") { while (text[i] >= "0" && text[i] <= "9") i++; }
    else fail("expected a number");
    if (text[i] === ".") {
      i++;
      if (!(text[i] >= "0" && text[i] <= "9")) fail("expected a fraction digit");
      while (text[i] >= "0" && text[i] <= "9") i++;
    }
    if (text[i] === "e" || text[i] === "E") {
      i++;
      if (text[i] === "+" || text[i] === "-") i++;
      if (!(text[i] >= "0" && text[i] <= "9")) fail("expected an exponent digit");
      while (text[i] >= "0" && text[i] <= "9") i++;
    }
    return text.slice(start, i);
  };
  const readLiteral = (word) => {
    if (text.slice(i, i + word.length) !== word) fail("unexpected token");
    i += word.length;
  };
  // Returns the raw source text when the value is a number, else null.
  const readValue = (depth) => {
    const c = text[i];
    if (c === "{") { readObject(depth); return null; }
    if (c === "[") { readArray(depth); return null; }
    if (c === '"') { readString(); return null; }
    if (c === "t") { readLiteral("true"); return null; }
    if (c === "f") { readLiteral("false"); return null; }
    if (c === "n") { readLiteral("null"); return null; }
    return readNumber();
  };
  const readArray = (depth) => {
    i++; ws();
    if (text[i] === "]") { i++; return; }
    for (;;) {
      ws(); readValue(depth + 1); ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "]") { i++; return; }
      fail("expected , or ] in array");
    }
  };
  const readObject = (depth) => {
    const members = depth === 0 ? new Map() : null;
    if (members) topLevel = members;
    i++; ws();
    if (text[i] === "}") { i++; return; }
    for (;;) {
      ws();
      const name = readString();
      ws();
      if (text[i] !== ":") fail("expected : after a member name");
      i++; ws();
      const literal = readValue(depth + 1);
      if (members) {
        const seen = members.get(name.value) ||
          { count: 0, escaped: false, numberLiterals: [] };
        seen.count++;
        seen.escaped = seen.escaped || name.escaped;
        if (literal !== null) seen.numberLiterals.push(literal);
        members.set(name.value, seen);
      }
      ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "}") { i++; return; }
      fail("expected , or } in object");
    }
  };

  try {
    ws();
    if (i >= text.length) fail("empty document");
    readValue(0);
    ws();
    if (i !== text.length) fail("trailing content after the JSON document");
  } catch (e) {
    return { ok: false, errors: [`document: not well-formed JSON — ${e.message}`], topLevel: null };
  }

  if (topLevel) {
    for (const [name, seen] of topLevel) {
      const isDisc = DISCRIMINATOR_KEYS.includes(name);
      if (seen.count > 1) {
        errors.push(isDisc
          ? `document: version discriminator "${name}" occurs ${seen.count} times at the top level of the received bytes — JSON.parse keeps only the last, so the document and the parsed record disagree about which schema (and which signature check) applies; refused as MALFORMED (fail closed, §12.6)`
          : `document: top-level member "${name}" occurs ${seen.count} times in the received bytes — a duplicated member is ambiguous about what was signed and what any two readers will see; refused as MALFORMED (fail closed, §12.6)`);
      }
      if (isDisc && seen.escaped) {
        errors.push(`document: version discriminator "${name}" is written with a \\u escape in the received bytes — a discriminator that only becomes itself after unescaping hides the version from every reader that has not parsed; refused as MALFORMED (fail closed, §12.6)`);
      }
      if (name === "record_version") {
        for (const literal of seen.numberLiterals) {
          if (!CANONICAL_UINT.test(literal))
            errors.push(`document: record_version is written as \`${literal}\` — JSON.parse folds that to the same double as the plain integer, so the bytes and the parsed version claim differ; a producer emits a bare integer (fail closed, §12.6)`);
        }
      }
    }
  }
  return { ok: errors.length === 0, errors, topLevel };
}

// Structural validation against the v1/v2/v3 field tables. Returns
// { ok, version, errors, document_checked } plus, on v3,
// `receipt_signature_valid` (the Object B Ed25519 envelope — deliberately NOT
// named `signature_valid`, which downstream verifiers already use for the
// DIFFERENT `signed_config` object).
// version: "v3"|"v2" (current) | "v1" (accepted-legacy) | "v0-live"
// (grandfathered) | "v0-check" (rejected legacy Schema K) | null (unrecognized).
//
// CONTRACT (§12.6), and it is a change: `r` may be EITHER the raw received
// document text (a string) or an already-parsed object.
//   * Anything that came off a wire, a file, or a URL fragment MUST be passed
//     as the TEXT. Only then are the document-level checks possible at all,
//     and only then does `document_checked: true` come back. `record` carries
//     the parsed object so the caller need not parse it twice.
//   * The object form remains supported for records this process MINTED (no
//     received bytes exist to check) and returns `document_checked: false`.
//     A `false` there means the version claim was never checked against any
//     document: a consumer must NOT read `ok: true` on that path as evidence
//     about what a peer sent. It is not a warning that can be ignored — it is
//     the difference between "this object is well formed" and "the bytes we
//     received say this".
//
// v3 verification is cryptographic: pass opts.ed25519Verify(message,
// signature, publicKey) -> boolean (Uint8Array args; e.g. tweetnacl's
// nacl.sign.detached.verify). Without it a v3 receipt FAILS validation with an
// explicit UNVERIFIED error — the module stays dependency-free and the caller
// cannot silently skip the check.
export function validateReceipt(r, opts = {}) {
  if (typeof r === "string") return validateReceiptDocument(r, opts);
  const out = validateParsedReceipt(r, opts);
  out.document_checked = false;
  return out;
}

// The wire entry point: scan the received bytes for the ambiguities
// `JSON.parse` would collapse, THEN parse those same untouched bytes and
// validate the record. Refuses before parsing if the document lies about its
// own version claim.
export function validateReceiptDocument(text, opts = {}) {
  const scan = scanReceiptDocument(text);
  if (!scan.ok)
    return { ok: false, version: null, errors: scan.errors, document_checked: true };
  let record;
  try {
    record = JSON.parse(text);
  } catch (e) {
    return { ok: false, version: null, document_checked: true,
      errors: [`document: not parseable JSON — ${e.message}`] };
  }
  const out = validateParsedReceipt(record, opts);
  out.document_checked = true;
  out.record = record;
  return out;
}

function validateParsedReceipt(r, opts = {}) {
  const errors = [];
  if (!isObj(r)) return { ok: false, version: null, errors: ["receipt is not an object"] };
  if ("authority_trusted" in r)
    errors.push("authority_trusted: verifier-computed only; forbidden in a receipt");

  // A version is claimed through exactly ONE of four discriminator key
  // families — six recognized version claims in total:
  //   1. seal_receipt                  ("v1" | "v2" — fleet JS producers)
  //   2. record_type + record_version  (host records: 2 → v2, 3 → v3)
  //   3. seal_live_receipt             ("v0" — grandfathered live demo)
  //   4. seal_check_receipt            (legacy Schema K, always refused)
  // A record presenting keys from MORE THAN ONE family is MALFORMED and is
  // refused before any classification: it is not a v2 record and not a v3
  // record; it is a document trying to be classified favourably. Concretely,
  // a signed v3 body with `seal_receipt: "v2"` bolted on would otherwise win
  // the v2 branch and skip Object B signature verification entirely — a
  // downgrade that turns `ok: true` into a forgery vector. No priority order
  // among the families is safe: preferring the highest version present merely
  // converts the downgrade into an upgrade attack. Fail closed instead.
  // "Present" = the key exists with a non-undefined value; JSON.parse never
  // yields undefined, so wire records are judged on key presence alone.
  // This gate reads the PARSED OBJECT, which is exactly its blind spot: a
  // document repeating one discriminator collapses to a single family here
  // and the gate has nothing to fire on. That case is caught earlier, on the
  // bytes, by scanReceiptDocument (§12.6) — the two rules are complements,
  // and only the document path runs both.
  const discFamilies = [];
  if (r.seal_receipt !== undefined) discFamilies.push("seal_receipt");
  if (r.record_type !== undefined || r.record_version !== undefined)
    discFamilies.push("record_type/record_version");
  if (r.seal_live_receipt !== undefined) discFamilies.push("seal_live_receipt");
  if (r.seal_check_receipt !== undefined) discFamilies.push("seal_check_receipt");
  if (discFamilies.length > 1) {
    return { ok: false, version: null,
      errors: [`conflicting version discriminators: ${discFamilies.join(" + ")} — a record claiming more than one schema version is malformed and refused (fail closed, §12.0)`] };
  }

  let version = null;
  if (r.seal_receipt === RECEIPT_SCHEMA_VERSION_V2) version = "v2";
  else if (r.record_type === "seal.authorization-decision" && r.record_version === 2) version = "v2";
  // Exact equality per version, ONE branch each — never a range match
  // (`record_version >= 2` would silently accept v4/v5, which is precisely
  // how an unspecified version becomes invisible). An unknown record_version
  // falls through to "no recognized version discriminator" and is refused.
  else if (r.record_type === "seal.authorization-decision" && r.record_version === 3) version = "v3";
  else if (r.seal_receipt === RECEIPT_SCHEMA_VERSION) version = "v1";
  else if (r.seal_live_receipt === "v0") version = "v0-live";
  else if ("seal_check_receipt" in r) {
    return { ok: false, version: "v0-check",
      errors: ["legacy Schema K (seal_check_receipt) — not v1-compatible; regenerate with a v1 producer (see docs/DECISION-RECEIPT-SCHEMA.md)"] };
  } else {
    return { ok: false, version: null, errors: ["no recognized version discriminator"] };
  }

  // §11.1 unparseable-request rule (seal-host main @ 3a74dbf): the kernel is
  // deliberately the more tolerant parser. On a line the producer could not
  // re-parse, the receipt carries request_parse_error + request_sha256 and
  // OMITS the structured request fields; requiring them here would restore to
  // the verifier the veto the producer was deliberately stripped of (§11.2).
  const unparseable = "request_parse_error" in r;
  if (unparseable) {
    if (typeof r.request_parse_error !== "string" || !r.request_parse_error)
      errors.push("request_parse_error: non-empty string when present");
    if (r.bypass === true)
      errors.push("request_parse_error: only a mediated receipt names a parse error");
    if (typeof r.request_sha256 !== "string" || !HEX64.test(r.request_sha256))
      errors.push("request_sha256: 64-hex string required on an unparseable-request receipt");
    for (const k of ["tool", "arguments", "args_hash", "canonical_request", "canonical_request_sha256"]) {
      if (k in r)
        errors.push(`${k}: must be absent on an unparseable-request receipt (a named parse error with structured request fields is fabrication)`);
    }
  } else {
    if (typeof r.tool !== "string" || !r.tool) errors.push("tool: non-empty string required");
    if (!isObj(r.arguments)) errors.push("arguments: object required");
    if (typeof r.canonical_request_sha256 !== "string" || !HEX64.test(r.canonical_request_sha256))
      errors.push("canonical_request_sha256: 64-hex string required");
    if ("request_sha256" in r && (typeof r.request_sha256 !== "string" || !HEX64.test(r.request_sha256)))
      errors.push("request_sha256: 64-hex string when present");
  }
  if (typeof r.bypass !== "boolean") errors.push("bypass: boolean required");
  if (!VERDICTS.includes(r.verdict)) errors.push(`verdict: one of ${VERDICTS.join("|")} required`);
  if (typeof r.reason !== "string") errors.push("reason: string required");
  if (!isObj(r.kernel_identity)) errors.push("kernel_identity: object required");
  if ("host_identity" in r && !isObj(r.host_identity))
    errors.push("host_identity: object when present");

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
    // §4 HARD SPLIT (v1, v2 and v3; v0-live merged blocks are grandfathered):
    // identity is the binary hash — asserted provenance lives in its own
    // block. A v1/v2/v3 kernel_identity carrying toolchain/axioms is INVALID.
    if (version === "v1" || version === "v2" || version === "v3") {
      for (const k of ["lean_toolchain", "axioms"]) {
        if (k in r.kernel_identity)
          errors.push(`kernel_identity.${k}: forbidden in ${version} (hard split, L0 §6.2) — move to asserted_provenance`);
      }
      if (typeof r.kernel_identity.self_verified !== "boolean")
        errors.push(`kernel_identity.self_verified: boolean required in ${version}`);
    }
  }
  if (isObj(r.host_identity)) {
    for (const k of ["native_executable_sha256", "lean_ffi_sha256"]) {
      if (typeof r.host_identity[k] !== "string" || !HEX64.test(r.host_identity[k]))
        errors.push(`host_identity.${k}: 64-hex string required`);
    }
    if (r.host_identity.equivalence !== "not_proven")
      errors.push("host_identity.equivalence: must be not_proven");
  }
  if ((version === "v1" || version === "v2" || version === "v3") && "asserted_provenance" in r) {
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

  // §12: v3 is purely additive over v2 — the full v2 body obligations apply
  // unchanged, then the release-authority extras and the Object B signature.
  if (version === "v2" || version === "v3") validateV2Extras(r, errors);
  if (version === "v3") {
    const receipt_signature_valid = validateV3Extras(r, errors, opts.ed25519Verify);
    return { ok: errors.length === 0, version, errors, receipt_signature_valid };
  }

  return { ok: errors.length === 0, version, errors };
}

// §11 checks beyond the shared v1 core. Derived hashes are RECOMPUTED here —
// a receipt asserting a hash its own fields do not produce is invalid.
function validateV2Extras(r, errors) {
  if ("action" in r && (typeof r.action !== "string" || !r.action))
    errors.push("action: non-empty string when present");

  if (r.bypass === false) {
    // §11.2: args_hash is required iff the producer parsed the wire line; on
    // an unparseable-request receipt its absence is enforced in validateReceipt.
    if (!("request_parse_error" in r)) {
      if (typeof r.args_hash !== "string" || !HEX64.test(r.args_hash))
        errors.push("args_hash: 64-hex string required when mediated (v2)");
      else if (isObj(r.arguments) && r.args_hash !== canonicalJsonSha256(r.arguments))
        errors.push("args_hash: does not equal sha256 of the canonical arguments serialization");
    }
  } else if ("args_hash" in r) {
    errors.push("args_hash: must be absent on bypass");
  }

  if (r.bypass === true) {
    if ("signed_config" in r) errors.push("signed_config: must be absent on bypass");
  } else if (!isObj(r.signed_config)) {
    errors.push("signed_config: object required when mediated (v2)");
  } else {
    const keys = Object.keys(r.signed_config);
    if (JSON.stringify(keys) !== JSON.stringify(SIGNED_CONFIG_KEY_ORDER))
      errors.push("signed_config: exact key order payload,signature,pubkey required");
    if (typeof r.signed_config.payload !== "string")
      errors.push("signed_config.payload: exact signed JSON string required");
    if (typeof r.signed_config.signature !== "string" || !HEX128.test(r.signed_config.signature))
      errors.push("signed_config.signature: 128-hex Ed25519 signature required");
    if (typeof r.signed_config.pubkey !== "string" || !HEX64.test(r.signed_config.pubkey))
      errors.push("signed_config.pubkey: 64-hex Ed25519 public key required");
  }

  // Approval block: v2 originally required it on every mediated ALLOW. Policy-v2
  // adds explicit policy ALLOW, which carries authorization=explicit_policy_allow
  // and no approval. Missing authorization remains accepted for legacy v2 ALLOW.
  if ("authorization" in r && !["approval", "explicit_policy_allow"].includes(r.authorization))
    errors.push("authorization: approval|explicit_policy_allow when present");
  if (r.bypass === true && "approval" in r) errors.push("approval: must be absent on bypass");
  if (r.bypass === false && r.verdict === "ALLOW") {
    const auth = r.authorization || "approval";
    if (auth === "approval" && !isObj(r.approval))
      errors.push("approval: object required for approval-authorized ALLOW");
    if (auth === "explicit_policy_allow" && "approval" in r)
      errors.push("approval: forbidden on explicit policy ALLOW");
    if (auth === "explicit_policy_allow" && Array.isArray(r.granted_capabilities) && r.granted_capabilities.length)
      errors.push("granted_capabilities: must be empty on explicit policy ALLOW");
  }
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

// --- §12: v3 release authority + Object B signature --------------------------
// Producer: seal-host rust/src/release.rs (attach_and_sign / ReceiptSigner).
// v3 adds four always-present signed fields (release_status, operation_id,
// durability_class, signature) and three ALLOW-only companions
// (release_valid_until, post_state_hash, release_frame).
//
// NAME COLLISION, deliberate and documented: v1 receipts may carry an optional
// live-demo HMAC field also called `signature` (different shape, unchecked
// here). The discriminators are disjoint keys (v1: `seal_receipt`; v3:
// `record_type`+`record_version`), so a v1 record can never reach this branch;
// a record carrying BOTH discriminator families is refused as MALFORMED by
// the dual-discriminator rule in validateReceipt (it never classifies at
// all, so it can neither downgrade to v2 nor reach this branch). Likewise
// `signed_config.signature`
// (config authority) and approval signatures are DIFFERENT objects under
// different keys — none of them is this envelope.

const SIGNATURE_KEYS_SORTED = ["algorithm", "domain", "encoding", "key_id", "public_key", "value"];
const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// Strict decoder for both alphabets. Standard padding is accepted on B64_STD
// only; non-alphabet characters and non-zero trailing bits are rejected
// (returns null — a malleable signature encoding must not verify).
function base64Bytes(input, alphabet) {
  if (typeof input !== "string") return null;
  let s = input;
  if (alphabet === B64_STD) s = s.replace(/=+$/, "");
  if (s.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let buf = 0, bits = 0, n = 0;
  for (const ch of s) {
    const v = alphabet.indexOf(ch);
    if (v < 0) return null;
    buf = (buf << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out[n++] = (buf >> bits) & 255; }
  }
  if (bits && (buf & ((1 << bits) - 1))) return null;
  return out.subarray(0, n);
}

// §12.2 preimage:  "seal.object-b/v1" || 0x00 || u64_be(len(bytes)) || bytes
// where bytes = the compact JSON of the record with `signature` removed, in
// the record's OWN stored key order.
//
// THE preserve_order CRUX: the producer serializes with serde_json's
// preserve_order feature, so the covered bytes are in producer INSERTION
// order, not sorted keys. Do NOT canonicalise or sort here — a sorted rebuild
// produces a preimage that verifies nothing. JSON.parse + JSON.stringify
// round-trips string-keyed member order faithfully; two honest limits, both
// fail CLOSED (signature refuses, never falsely accepts): (1) JS reorders
// integer-like member names to the front, so a producer map with such keys
// out of that order cannot be re-serialized byte-identically; (2) numbers
// outside the exact-double range (|n| >= 2^53, or any non-shortest float
// spelling) lose their source bytes at JSON.parse.
export function receiptSignaturePreimage(record) {
  const unsigned = {};
  for (const k of Object.keys(record)) if (k !== "signature") unsigned[k] = record[k];
  const body = new TextEncoder().encode(JSON.stringify(unsigned));
  const out = new Uint8Array(17 + 8 + body.length);
  out.set(new TextEncoder().encode(RECEIPT_SIGNATURE_DOMAIN)); // 16 chars…
  out[16] = 0; // …plus the trailing NUL: SIGNATURE_DOMAIN is 17 bytes.
  let len = body.length;
  for (let i = 24; i >= 17; i--) { out[i] = len % 256; len = Math.floor(len / 256); }
  out.set(body, 25);
  return out;
}

// §12.1 operation-state bind: sha256 of the exact compact serde_json bytes
// {"operation_id":…,"release_frame_sha256":…} (this insertion order).
export function postStateHash(operationId, frameSha256) {
  return sha256Hex(new TextEncoder().encode(
    `{"operation_id":${JSON.stringify(operationId)},"release_frame_sha256":${JSON.stringify(frameSha256)}}`));
}

// Shape + cryptographic check of the Object B envelope. Returns
// { receipt_signature_valid, errors }. receipt_signature_valid is true ONLY
// when the shape is exact AND the Ed25519 primitive ran and accepted; an
// absent signature, a malformed envelope, or a missing primitive all fail.
// Trust caveat (§12.4): a passing check binds the record to the EMBEDDED
// public key; binding that key to a deployment needs an out-of-band pin.
export function verifyReceiptSignature(record, ed25519Verify) {
  const errors = [];
  const s = isObj(record) ? record.signature : undefined;
  if (!isObj(s)) {
    return { receipt_signature_valid: false,
      errors: ["signature: Object B envelope required on every v3 receipt (absent means invalid, not optional)"] };
  }
  if (JSON.stringify(Object.keys(s).sort()) !== JSON.stringify(SIGNATURE_KEYS_SORTED))
    errors.push("signature: exactly the members domain,algorithm,public_key,key_id,encoding,value required");
  if (s.domain !== RECEIPT_SIGNATURE_DOMAIN)
    errors.push(`signature.domain: must be ${RECEIPT_SIGNATURE_DOMAIN}`);
  if (s.algorithm !== "Ed25519") errors.push("signature.algorithm: must be Ed25519");
  if (s.encoding !== "base64url-nopad") errors.push("signature.encoding: must be base64url-nopad");
  if (typeof s.public_key !== "string" || !HEX64.test(s.public_key))
    errors.push("signature.public_key: 64-hex Ed25519 public key required");
  if (typeof s.key_id !== "string" || !HEX64.test(s.key_id))
    errors.push("signature.key_id: 64-hex string required");
  const sigBytes = base64Bytes(s.value, B64_URL);
  if (sigBytes === null || sigBytes.length !== 64)
    errors.push("signature.value: base64url-nopad of a 64-byte Ed25519 signature required");
  if (errors.length === 0) {
    const pub = hexToBytes(s.public_key);
    if (s.key_id !== sha256Hex(pub)) {
      errors.push("signature.key_id: does not equal sha256 of the public key bytes");
    } else if (typeof ed25519Verify !== "function") {
      errors.push("signature: UNVERIFIED — v3 validation requires an Ed25519 primitive; pass opts.ed25519Verify(message, signature, publicKey) (fail closed, never skipped)");
    } else if (ed25519Verify(receiptSignaturePreimage(record), sigBytes, pub) !== true) {
      errors.push("signature.value: Ed25519 verification failed over the seal.object-b/v1 preimage (record was mutated after signing, or signed by other bytes)");
    }
  }
  return { receipt_signature_valid: errors.length === 0, errors };
}

// §12 checks beyond the v2 body. Returns receipt_signature_valid.
function validateV3Extras(r, errors, ed25519Verify) {
  if (!RELEASE_STATUSES.includes(r.release_status))
    errors.push(`release_status: one of ${RELEASE_STATUSES.join("|")} required (v3)`);
  if (typeof r.operation_id !== "string" || !HEX64.test(r.operation_id))
    errors.push("operation_id: 64-hex string (32 random bytes) required (v3)");
  if (!DURABILITY_CLASSES.includes(r.durability_class))
    errors.push(`durability_class: one of ${DURABILITY_CLASSES.join("|")} required (v3)`);

  if (r.verdict === "ALLOW") {
    // Release authority: the exact frame the host may forward, bound to the
    // signed operation_id and to the operation-state burn entry.
    if (r.release_status === "NOT_APPLICABLE")
      errors.push("release_status: must not be NOT_APPLICABLE on ALLOW (PENDING|UNKNOWN|RELEASED)");
    if (!Number.isInteger(r.release_valid_until) || r.release_valid_until < 0)
      errors.push("release_valid_until: non-negative integer (epoch ms) required on ALLOW (v3)");
    const pshOk = typeof r.post_state_hash === "string" && HEX64.test(r.post_state_hash);
    if (!pshOk) errors.push("post_state_hash: 64-hex string required on ALLOW (v3)");
    const f = r.release_frame;
    if (!isObj(f)) {
      errors.push("release_frame: object required on ALLOW (v3)");
    } else {
      if (f.encoding !== "base64") errors.push("release_frame.encoding: must be base64");
      if (!Number.isInteger(f.length) || f.length < 0)
        errors.push("release_frame.length: non-negative integer required");
      if (typeof f.sha256 !== "string" || !HEX64.test(f.sha256))
        errors.push("release_frame.sha256: 64-hex string required");
      const frame = base64Bytes(f.base64, B64_STD);
      if (frame === null) {
        errors.push("release_frame.base64: base64 string required");
      } else {
        if (frame.length !== f.length)
          errors.push("release_frame.length: does not equal the decoded frame length");
        const frameSha = sha256Hex(frame);
        if (typeof f.sha256 === "string" && HEX64.test(f.sha256) && frameSha !== f.sha256)
          errors.push("release_frame.sha256: does not equal sha256 of the decoded frame bytes");
        // Producer strips one trailing \r\n or \n before parsing the body.
        let end = frame.length;
        if (end >= 2 && frame[end - 2] === 13 && frame[end - 1] === 10) end -= 2;
        else if (end >= 1 && frame[end - 1] === 10) end -= 1;
        let frameJson;
        try { frameJson = JSON.parse(new TextDecoder().decode(frame.subarray(0, end))); }
        catch { errors.push("release_frame: decoded frame is not a JSON object"); }
        if (frameJson !== undefined &&
            (!isObj(frameJson) || frameJson.operation_id !== r.operation_id))
          errors.push("release_frame: frame operation_id does not equal the signed top-level operation_id (the id must be forwarded unchanged)");
        if (pshOk && typeof r.operation_id === "string" &&
            r.post_state_hash !== postStateHash(r.operation_id, frameSha))
          errors.push("post_state_hash: does not equal sha256 of the {operation_id, release_frame_sha256} operation state (bind broken)");
      }
    }
  } else {
    if (RELEASE_STATUSES.includes(r.release_status) && r.release_status !== "NOT_APPLICABLE")
      errors.push("release_status: must be NOT_APPLICABLE on a non-ALLOW receipt");
    for (const k of ["release_valid_until", "post_state_hash", "release_frame"]) {
      if (k in r) errors.push(`${k}: ALLOW-only release authority; must be absent on a non-ALLOW receipt (v3)`);
    }
  }

  const sig = verifyReceiptSignature(r, ed25519Verify);
  errors.push(...sig.errors);
  return sig.receipt_signature_valid;
}
