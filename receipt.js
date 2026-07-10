// SPDX-License-Identifier: Apache-2.0
// Verify a deep-linked seal receipt (e.g. from seal-live-demo) entirely in-browser.
// Trusts nothing the receipt claims: it re-hashes the request, re-derives the verdict
// through the SAME verified kernel binary with the receipt's own policy, and
// self-verifies the kernel sha256. The receipt rides in the URL #fragment, which the
// browser never sends to a server. No backend.
//
// Accepts schema v1 (seal_receipt) and the legacy v0-live dialect
// (seal_live_receipt) per docs/DECISION-RECEIPT-SCHEMA.md; legacy
// Schema K objects are rejected with the spec's regenerate error.
import { decideRaw, verifyKernelSha } from "./kernel.js";
import {
  canonicalRequest, canonicalRequestSha256, capabilityTargetsFromPolicy, validateReceipt,
} from "./receipt-format.js";

export function b64urlToStr(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bytes = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

// Human summary of the call a receipt mediated. Recognizes the seal-live-demo
// argument shape ({operation, table}); every other valid v1 receipt gets a
// generic tool+arguments summary so real receipts never render "undefined".
export function callSummary(receipt) {
  const a = (receipt && typeof receipt.arguments === "object" && !Array.isArray(receipt.arguments)
    && receipt.arguments) || {};
  if (typeof a.operation === "string" && typeof a.table === "string") {
    return { demo: true, operation: a.operation, table: a.table };
  }
  let argsJson = "{}";
  try { argsJson = JSON.stringify(a); } catch { /* unserializable — keep the placeholder */ }
  if (argsJson.length > 120) argsJson = argsJson.slice(0, 120) + "…";
  const tool = receipt && typeof receipt.tool === "string" && receipt.tool ? receipt.tool : "unknown tool";
  return { demo: false, tool, argsJson };
}

// Read #receipt=<base64url> from the URL fragment. Returns the receipt object or null.
export function decodeReceiptParam() {
  const params = new URLSearchParams(location.hash.slice(1));
  const enc = params.get("receipt");
  if (!enc) return null;
  return JSON.parse(b64urlToStr(enc));
}

// Independently verify a receipt. Returns { formatOk, kernelShaMatch,
// requestHashMatch, rederived, verdictMatch, mediated, allGood, ... } — every
// field recomputed locally per the spec's §7 verifier obligations.
export async function verifyReceipt(receipt) {
  const out = { receipt };

  // 0. Shape first: version discriminator, field table, hard-split rule,
  //    stored-line-vs-derived-line equality. A malformed receipt never
  //    reaches the kernel.
  const shape = validateReceipt(receipt);
  out.formatOk = shape.ok;
  out.formatVersion = shape.version;
  out.formatErrors = shape.errors;
  if (!shape.ok) { out.mediated = null; out.allGood = false; return out; }

  // 1. Bypass receipts record that seal was REMOVED from the path. There is
  //    no kernel verdict to verify — report NOT MEDIATED, never "verified".
  if (receipt.bypass) {
    out.mediated = false;
    out.notMediated = "bypass receipt — seal was removed from the path; no kernel verdict exists";
    out.allGood = false;
    return out;
  }
  out.mediated = true;

  // 2. The kernel binary in this browser is the audited one, AND it is the same
  //    binary the receipt names.
  const sha = await verifyKernelSha();
  out.kernelSha = sha.computed;
  out.kernelShaMatch = sha.match && receipt.kernel_identity.wasm_sha256 === sha.computed;

  // 3. §2/§7: derive the canonical line from the SAME (tool, arguments) that
  //    feeds re-derivation below; validateReceipt already pinned any stored
  //    canonical_request to this exact line.
  out.requestHash = canonicalRequestSha256(receipt.tool, receipt.arguments);
  out.requestLine = canonicalRequest(receipt.tool, receipt.arguments);
  out.requestHashMatch = out.requestHash === receipt.canonical_request_sha256;

  // 4. Re-derive the verdict through the same kernel with the receipt's own
  //    policy. Approval targets recomputed per §3 (un-hashed entries via the
  //    policy target spec; opaque {target} entries verbatim, counted).
  out.rederived = null; out.verdictMatch = null;
  const grants = capabilityTargetsFromPolicy(receipt.kernel_config, receipt.granted_capabilities);
  out.opaqueGrants = grants.opaque;   // grants whose pre-image the producer did not hold
  out.grantErrors = grants.errors;
  if (grants.errors.length === 0) {
    try {
      const res = await decideRaw(receipt.kernel_config, {
        tool: receipt.tool, args: receipt.arguments, approvals: grants.approvals,
        now: receipt.now ?? 1000,
      });
      out.rederived = res.parsed.verdict === "DENY" ? "BLOCK" : res.parsed.verdict;
      out.rederivedReason = res.parsed.reason;
      out.verdictMatch = out.rederived === receipt.verdict;
      out.emittedBytesMatch = typeof receipt.emitted_bytes === "string"
        ? res.raw === receipt.emitted_bytes : null;
    } catch (e) { out.rederiveError = e.message; }
  }

  out.allGood = out.formatOk && out.kernelShaMatch && out.requestHashMatch &&
    out.verdictMatch === true && out.grantErrors.length === 0 &&
    out.emittedBytesMatch !== false;
  // Informational only — gates nothing. Opaque grants are this box's defining
  // property (fire-your-own-target accepts raw commitments), not a shortfall:
  // the UI names the boundary instead of warning about it.
  out.hasOpaqueGrants = out.opaqueGrants > 0;
  return out;
}
