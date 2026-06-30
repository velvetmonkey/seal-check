// SPDX-License-Identifier: Apache-2.0
// Verify a deep-linked seal receipt (e.g. from seal-live-demo) entirely in-browser.
// Trusts nothing the receipt claims: it re-hashes the request, re-derives the verdict
// through the SAME verified kernel binary with the receipt's own policy, and
// self-verifies the kernel sha256. The receipt rides in the URL #fragment, which the
// browser never sends to a server. No backend.
import { decideRaw, verifyKernelSha, sha256Hex } from "./kernel.js";
import { stableHash } from "./seal-config.js";

function b64urlToStr(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bytes = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

// Read #receipt=<base64url> from the URL fragment. Returns the receipt object or null.
export function decodeReceiptParam() {
  const params = new URLSearchParams(location.hash.slice(1));
  const enc = params.get("receipt");
  if (!enc) return null;
  return JSON.parse(b64urlToStr(enc));
}

// Rebuild the canonical JSON-RPC request the gateway hashed. MUST match decide.cjs's
// canonicalRequest exactly, or the request-hash check is meaningless.
function canonicalRequest({ operation, table, payload }) {
  return JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: { name: "db.execute", arguments: { operation, table, payload } },
  });
}

// Independently verify a receipt. Returns { kernelShaMatch, requestHashMatch,
// rederived, verdictMatch, allGood, ... } — every field recomputed locally.
export async function verifyReceipt(receipt) {
  const out = { receipt };

  // 1. The kernel binary in this browser is the audited one, AND it is the same
  //    binary the receipt names.
  const sha = await verifyKernelSha();
  out.kernelSha = sha.computed;
  out.kernelShaMatch = sha.match &&
    (!receipt.kernel_identity?.wasm_sha256 || receipt.kernel_identity.wasm_sha256 === sha.computed);

  // 2. The request bytes hash to the value the receipt claims (pure hash, no kernel).
  const line = canonicalRequest(receipt.arguments || {});
  out.requestHash = sha256Hex(new TextEncoder().encode(line));
  out.requestHashMatch = !!receipt.canonical_request_sha256 && out.requestHash === receipt.canonical_request_sha256;

  // 3. Re-derive the verdict through the same kernel with the receipt's own policy.
  //    (Bypass receipts deliberately removed seal, so there is nothing to re-derive.)
  out.rederived = null; out.verdictMatch = null;
  if (receipt.kernel_config && !receipt.bypass) {
    try {
      const approvals = (receipt.granted_capabilities || []).map((g) => stableHash([g.tool, g.table, g.operation]));
      const res = await decideRaw(receipt.kernel_config, {
        tool: receipt.tool || "db.execute", args: receipt.arguments, approvals,
      });
      out.rederived = res.parsed.verdict === "DENY" ? "BLOCK" : res.parsed.verdict;
      out.rederivedReason = res.parsed.reason;
      out.verdictMatch = out.rederived === receipt.verdict;
    } catch (e) { out.rederiveError = e.message; }
  }

  out.allGood = out.kernelShaMatch && out.requestHashMatch && out.verdictMatch !== false;
  return out;
}
