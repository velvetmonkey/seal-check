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
import { decideSignedRaw, verifyKernelSha } from "./kernel.js";
import {
  HOST_AUDIT_VERDICT_MAP,
  canonicalRequest, canonicalRequestSha256, capabilityTargetsFromPolicy, sha256Hex, validateReceipt,
} from "./receipt-format.js";

// Declared verification profile of THIS copy (seal-assurance-kit
// docs/VERIFY-PROFILES.md): P-ENFORCE — the production receipt gate.
// signed_config binding is required, the top verdict requires the
// trust-anchor pin (`expectedConfigPubkey`), and the outcome set
// {authorised, authorised-unparseable, unpinned, failure} maps to the CLI's
// 0/4/3/1 exits and the browser's four states (the browser deployment is
// unpinned, so its ceiling is UNPINNED — ENF-4). The fleet differentials key
// their expected agreement/divergence off this declaration; changing it is a
// design decision, not a refactor.
export const VERIFY_PROFILE = "P-ENFORCE";

// §11.1 helpers for unparseable-request receipts -----------------------------

// Ed25519 over the exact signed_config payload bytes — the same check
// seal_init performs, done directly because the kernel cannot be invoked
// without a parseable call.
async function verifyConfigSignature(sc) {
  try {
    if (typeof sc.pubkey !== "string" || typeof sc.signature !== "string" ||
        typeof sc.payload !== "string") return false;
    const bytes = (hex) => Uint8Array.from(hex.match(/../g), (b) => parseInt(b, 16));
    const key = await globalThis.crypto.subtle.importKey(
      "raw", bytes(sc.pubkey), { name: "Ed25519" }, false, ["verify"]);
    return await globalThis.crypto.subtle.verify(
      "Ed25519", key, bytes(sc.signature), new TextEncoder().encode(sc.payload));
  } catch {
    return false;
  }
}

// The kernel material an unparseable-request receipt carries must at least
// agree with itself: the audit embedded in emitted_bytes names the same
// verdict and certs the receipt asserts. Consistency, not replay.
function auditConsistent(receipt) {
  try {
    const audit = JSON.parse(JSON.parse(receipt.emitted_bytes).audit);
    return HOST_AUDIT_VERDICT_MAP[audit.verdict] === receipt.verdict &&
      JSON.stringify(audit.certs) === JSON.stringify(receipt.certs);
  } catch {
    return false;
  }
}

// The kernel's own commitment to the bytes it judged: Host/Audit.lean puts
// sha256 of the exact judged line into the audit inside emitted_bytes. This
// is what makes the pairing of kernel material to request identity
// kernel-attested rather than host-asserted.
function auditRequestHash(emittedBytes) {
  try {
    const h = JSON.parse(JSON.parse(emittedBytes).audit).request_sha256;
    return typeof h === "string" && /^[0-9a-f]{64}$/.test(h) ? h : null;
  } catch {
    return null;
  }
}

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
  // §11.1 unparseable-request receipt: the wire line the kernel judged could
  // not be re-parsed, so there is no (tool, arguments) to summarize — only the
  // raw line identity.
  if (receipt && typeof receipt.request_parse_error === "string") {
    return { demo: false, unparseable: true,
      rawLineShort: String(receipt.request_sha256 || "").slice(0, 12) + "…" };
  }
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

// Read #receipt=<base64url> from the URL fragment. Returns the receipt
// DOCUMENT — the raw JSON text exactly as it was carried — or null.
// §12.6: this is what a verifier must hand to validateReceipt/verifyReceipt.
// Parsing here and passing the object on would throw away the duplicate
// members, escaped key spellings, and numeric spellings that decide which
// version claim the document actually makes.
export function decodeReceiptDocument() {
  const params = new URLSearchParams(location.hash.slice(1));
  const enc = params.get("receipt");
  if (!enc) return null;
  return b64urlToStr(enc);
}

// Parsed-object form of the same link. Kept for callers that only want to READ
// the fields; it is document-blind and must not be used as the input to
// verification (see decodeReceiptDocument).
export function decodeReceiptParam() {
  const text = decodeReceiptDocument();
  return text === null ? null : JSON.parse(text);
}

// Independently verify a receipt. Returns { formatOk, kernelShaMatch,
// requestHashMatch, rederived, verdictMatch, mediated, allGood, ... } — every
// field recomputed locally per the spec's §7 verifier obligations.
// §12.6 CONTRACT: `input` is EITHER the raw received document text (a string)
// — required for anything that arrived from a link, a file, or a peer — or an
// object this process minted itself. Only the text form can be checked for the
// wire ambiguities `JSON.parse` collapses (duplicate discriminator members
// above all), and only it comes back with `document_checked: true`.
export async function verifyReceipt(input, { expectedConfigPubkey } = {}) {
  // 0. Shape first: document-level ambiguity, version discriminator, field
  //    table, hard-split rule, stored-line-vs-derived-line equality. A
  //    malformed receipt never reaches the kernel.
  const fromDocument = typeof input === "string";
  const shape = validateReceipt(input);
  const receipt = fromDocument ? (shape.record ?? null) : input;

  const out = {
    receipt,
    signature_valid: false,
    kernel_replay_consistent: false,
    authority_trusted: false,
    config_freshness: null,
    outcome: "failure",
    allGood: false,
    bindingErrors: [],
    document_checked: shape.document_checked === true,
  };

  out.formatOk = shape.ok;
  out.formatVersion = shape.version;
  out.formatErrors = shape.errors;
  if (!shape.ok) { out.mediated = null; return out; }

  // 1. Bypass receipts record that seal was REMOVED from the path. There is
  //    no kernel verdict to verify — report NOT MEDIATED, never "verified".
  if (receipt.bypass) {
    out.mediated = false;
    out.notMediated = "bypass receipt — seal was removed from the path; no kernel verdict exists";
    return out;
  }
  out.mediated = true;

  // §11.1 unparseable-request receipt: the kernel judged a wire line the
  // producer could not re-parse. request_sha256 (SHA-256 of the raw line) is
  // the only request commitment; canonical re-derivation and kernel replay
  // both need the (tool, arguments) the receipt honestly does not carry.
  // Everything else — kernel identity, signed-config binding, config
  // signature, kernel-material consistency, authority pin — is still
  // verified, and the outcome is its own reduced-scope state: never a bare
  // PASS, never a fabricated mismatch.
  out.unparseableRequest = typeof receipt.request_parse_error === "string";

  const signedConfig = receipt.signed_config;
  const pinSupplied = expectedConfigPubkey !== undefined;
  if (pinSupplied && (typeof expectedConfigPubkey !== "string" || !/^[0-9a-f]{64}$/.test(expectedConfigPubkey))) {
    out.pinError = "expectedConfigPubkey must be 64 lowercase hex characters";
  } else if (!signedConfig || typeof signedConfig.pubkey !== "string") {
    out.authority_trusted = false;
  } else if (!pinSupplied) {
    out.authority_trusted = "unpinned";
  } else {
    out.authority_trusted = expectedConfigPubkey === signedConfig.pubkey;
    if (!out.authority_trusted) out.pinError = "unauthorised config signer";
  }

  // 2. The kernel binary in this browser is the audited one, AND it is the same
  //    binary the receipt names.
  const sha = await verifyKernelSha();
  out.kernelSha = sha.computed;
  out.kernelShaMatch = sha.match && receipt.kernel_identity.wasm_sha256 === sha.computed;

  // 3. §2/§7: derive the canonical line from the SAME (tool, arguments) that
  //    feeds re-derivation below; validateReceipt already pinned any stored
  //    canonical_request to this exact line. On an unparseable-request receipt
  //    no canonical re-derivation is possible: report that as its own state,
  //    never a match (undefined === undefined is not verification) and never
  //    a mismatch.
  if (out.unparseableRequest) {
    out.requestHash = null;
    out.requestLine = null;
    out.requestHashMatch = null;
    out.rawLineIdentity = receipt.request_sha256;
    out.requestIdentityNote = "no canonical re-derivation possible; request identity is the raw line hash (request_sha256), kernel-attested via the audit's own commitment";
  } else {
    out.requestHash = canonicalRequestSha256(receipt.tool, receipt.arguments);
    out.requestLine = canonicalRequest(receipt.tool, receipt.arguments);
    out.requestHashMatch = out.requestHash === receipt.canonical_request_sha256;
  }

  // 4. Bind the displayed config to the exact bytes authenticated by df42.
  //    No binding failure is allowed to reach seal_decide.
  let signedPayload = null;
  let freshnessCandidate = null;
  if (!signedConfig || typeof signedConfig.payload !== "string") {
    out.bindingErrors.push("signed_config payload unavailable");
  } else {
    try {
      signedPayload = JSON.parse(signedConfig.payload);
      if (JSON.stringify(signedPayload) !== signedConfig.payload)
        out.bindingErrors.push("signed_config.payload is not its byte-identical compact reconstruction");
      if (JSON.stringify(receipt.kernel_config) !== signedConfig.payload)
        out.bindingErrors.push("kernel_config does not byte-equal signed_config.payload");
      if (receipt.approval && receipt.approval.policy_hash !==
          sha256Hex(new TextEncoder().encode(signedConfig.payload)))
        out.bindingErrors.push("approval.policy_hash does not equal sha256(signed_config.payload)");
      if (!signedPayload || !Number.isInteger(signedPayload.epoch) || signedPayload.epoch < 0) {
        out.bindingErrors.push("signed config requires a non-negative integer epoch");
      } else {
        freshnessCandidate = { field: "epoch", value: signedPayload.epoch, rollback_enforced: false };
      }
    } catch (error) {
      out.bindingErrors.push("signed_config.payload is not valid JSON: " + error.message);
    }
  }
  out.bindingOk = out.bindingErrors.length === 0;

  // 5. Resolve grants from the authenticated policy, then replay its exact
  //    envelope through df42. The verifier never invokes the test signer.
  //    An unparseable-request receipt cannot be replayed (no tool/arguments):
  //    instead, verify the Ed25519 config signature directly, check the
  //    kernel material the receipt DOES carry (emitted_bytes audit verdict +
  //    certs) for internal consistency, and check the KERNEL-ATTESTED request
  //    binding: the audit's request_sha256 (the kernel's own hash of the
  //    judged bytes) must equal the receipt's request_sha256. The pairing is
  //    kernel-attested now, no longer host-asserted. Honest residual that
  //    remains: without replay, the authenticity of the kernel blob itself
  //    still rests on the producing host's transcript.
  out.rederived = null; out.verdictMatch = null;
  const grants = capabilityTargetsFromPolicy(signedPayload, receipt.granted_capabilities);
  out.opaqueGrants = grants.opaque;   // grants whose pre-image the producer did not hold
  out.grantErrors = grants.errors;
  if (out.unparseableRequest) {
    out.replayUnavailable = "unparseable-request receipt — no (tool, arguments) to replay";
    if (out.bindingOk && grants.errors.length === 0 && signedConfig) {
      out.signature_valid = await verifyConfigSignature(signedConfig);
      out.config_freshness = out.signature_valid ? freshnessCandidate : null;
    }
    out.kernelMaterialConsistent = auditConsistent(receipt);
    const kernelHash = auditRequestHash(receipt.emitted_bytes);
    out.kernelRequestBinding = kernelHash !== null && kernelHash === receipt.request_sha256;
  } else if (out.bindingOk && grants.errors.length === 0) {
    try {
      const res = await decideSignedRaw(signedConfig, {
        tool: receipt.tool, args: receipt.arguments, approvals: grants.approvals,
        now: receipt.now ?? 1000,
      });
      out.signature_valid = res.signature_valid;
      if (!res.signature_valid) {
        out.rederiveError = "seal_init failed: " + res.initError;
      } else {
        out.config_freshness = freshnessCandidate;
        out.rederived = res.parsed.verdict === "DENY" ? "BLOCK" : res.parsed.verdict;
        out.rederivedReason = res.parsed.reason;
        out.verdictMatch = out.rederived === receipt.verdict;
        // Kernel-attested request binding, parseable side. A native-host
        // receipt carries the hash of the ACTUAL wire line (request_sha256);
        // browser/kit-minted receipts carry no top-level request_sha256 and
        // the judged line IS the canonical line.
        const expectedHash = typeof receipt.request_sha256 === "string"
          ? receipt.request_sha256 : out.requestHash;
        const storedKernelHash = typeof receipt.emitted_bytes === "string"
          ? auditRequestHash(receipt.emitted_bytes) : null;
        out.kernelRequestBinding = storedKernelHash !== null && storedKernelHash === expectedHash;
        // Replay reconstructs the CANONICAL id=1 line, so the replayed
        // audit's request commitment legitimately differs whenever the
        // actual wire line differed. Compare byte-identical MODULO that one
        // kernel-derived token (pinned independently just above); the token
        // must occur exactly once for the substitution to be byte-safe.
        // Strictly stronger than plain equality, which this degenerates to
        // when the hashes agree.
        if (typeof receipt.emitted_bytes === "string") {
          const replayedHash = auditRequestHash(res.raw);
          const substitutable = replayedHash !== null && storedKernelHash !== null &&
            res.raw.split(replayedHash).length === 2;
          out.emittedBytesMatch = substitutable &&
            res.raw.replace(replayedHash, storedKernelHash) === receipt.emitted_bytes;
        } else {
          out.emittedBytesMatch = null;
        }
        out.kernel_replay_consistent = out.verdictMatch === true && out.emittedBytesMatch === true;
      }
    } catch (e) { out.rederiveError = e.message; }
  }

  // Reduced-scope core for unparseable-request receipts: everything the
  // receipt carries is verified; what it honestly cannot carry (canonical
  // request re-derivation, kernel replay) is excluded rather than failed.
  const verificationCore = out.unparseableRequest
    ? out.formatOk && out.kernelShaMatch && out.bindingOk &&
      out.grantErrors.length === 0 && out.signature_valid &&
      out.kernelMaterialConsistent === true && out.kernelRequestBinding === true
    : out.formatOk && out.kernelShaMatch && out.requestHashMatch &&
      out.bindingOk && out.grantErrors.length === 0 && out.signature_valid &&
      out.kernel_replay_consistent && out.kernelRequestBinding === true;
  out.verificationCore = verificationCore;
  out.outcome = !verificationCore || out.authority_trusted === false
    ? "failure"
    : out.authority_trusted !== true ? "unpinned"
    : out.unparseableRequest ? "authorised-unparseable" : "authorised";
  out.allGood = out.outcome === "authorised";
  // Informational only — gates nothing. Opaque grants are this box's defining
  // property (fire-your-own-target accepts raw commitments), not a shortfall:
  // the UI names the boundary instead of warning about it.
  out.hasOpaqueGrants = out.opaqueGrants > 0;
  return out;
}
