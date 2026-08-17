// SPDX-License-Identifier: Apache-2.0
// Plain-language, field-for-field receipt summary shared by both browser pages.
// This module deliberately does not parse, validate, canonicalize, or hash a
// receipt. Those jobs remain in receipt-format.js and receipt.js.
import { KERNEL_HASH_SCOPE_LIMIT_TEXT } from "./page-claims.js";

function present(receipt, field) {
  return Object.prototype.hasOwnProperty.call(receipt || {}, field);
}

function valueOrAbsent(receipt, field) {
  return present(receipt, field) ? String(receipt[field]) : "absent";
}

function readableJson(value) {
  try { return JSON.stringify(value); }
  catch { return "unrenderable value"; }
}

function pathValueOrAbsent(receipt, path) {
  let current = receipt;
  for (const segment of path) {
    if (!current || typeof current !== "object" || !Object.prototype.hasOwnProperty.call(current, segment)) {
      return "absent";
    }
    current = current[segment];
  }
  return String(current);
}

function certDecision(cert) {
  if (!cert || typeof cert !== "object") return "an unreadable kernel entry";
  const kernel = present(cert, "kernel") ? String(cert.kernel) : "an unnamed kernel";
  return `${kernel} (${present(cert, "verdict") ? String(cert.verdict) : "no recorded verdict"})`;
}

function certKernel(cert) {
  return cert && typeof cert === "object" && present(cert, "kernel")
    ? String(cert.kernel) : "an unnamed kernel";
}

function comparableVerdict(value) {
  const normalized = String(value).toUpperCase();
  return normalized === "DENY" ? "BLOCK" : normalized;
}

function contradictionText(receipt, certs, allowingCerts, denyingCerts) {
  const contradictions = [];
  const headline = comparableVerdict(receipt.verdict);
  const determinateCerts = certs ? certs.filter((cert) => {
    const decision = cert && comparableVerdict(cert.verdict);
    return decision === "ALLOW" || decision === "BLOCK";
  }) : [];
  const disagreeingCerts = determinateCerts.filter((cert) => comparableVerdict(cert.verdict) !== headline);

  // The top-level decision is a claim about the same decision recorded by the
  // per-gate certs.  A split is useful context, but it is not orderly when a
  // determinate cert says the opposite of that top-level claim.
  if ((headline === "ALLOW" || headline === "BLOCK") && disagreeingCerts.length) {
    contradictions.push(`CONFLICT: verdict says ${headline} but per-gate results include ${disagreeingCerts.map(certDecision).join("; ")}.`);
  }
  if (headline === "BLOCK" && certs && certs.length && denyingCerts.length === 0) {
    contradictions.push("CONFLICT: verdict says BLOCK but no per-gate result records a denying gate.");
  }
  if (
    headline === "BLOCK" &&
    present(receipt, "deny_kernel") &&
    receipt.deny_kernel != null &&
    denyingCerts.length &&
    !denyingCerts.some((cert) => certKernel(cert) === String(receipt.deny_kernel))
  ) {
    contradictions.push(`CONFLICT: deny_kernel says ${String(receipt.deny_kernel)} but the denying per-gate results are ${denyingCerts.map(certKernel).join(" and ")}.`);
  }
  if (headline === "ALLOW" && present(receipt, "deny_kernel") && receipt.deny_kernel != null) {
    contradictions.push(`CONFLICT: verdict says ALLOW but deny_kernel says ${String(receipt.deny_kernel)}.`);
  }
  return contradictions.join(" ");
}

// Each entry carries the exact receipt field(s) which support its text. Keeping
// that map beside the prose prevents the two browser surfaces from drifting.
export function receiptSummaryEntries(receipt) {
  const r = receipt || {};
  const certs = Array.isArray(r.certs) ? r.certs : null;
  const certText = certs === null ? "certs is absent or is not an array" :
    certs.length ? certs.map(certDecision).join("; ") : "certs is an empty array";
  const headline = valueOrAbsent(r, "verdict");
  const denyKernel = valueOrAbsent(r, "deny_kernel");
  const allowingCerts = certs ? certs.filter((c) => c && comparableVerdict(c.verdict) === "ALLOW") : [];
  const denyingCerts = certs ? certs.filter((c) => c && comparableVerdict(c.verdict) === "BLOCK") : [];
  const split = comparableVerdict(r.verdict) === "BLOCK" && allowingCerts.length && denyingCerts.length;
  const contradiction = contradictionText(r, certs, allowingCerts, denyingCerts);
  const decision = `The receipt states ${headline}; deny_kernel is ${denyKernel}. Per-gate results: ${certText}.` +
    (split
      ? ` This is a split decision: ${denyingCerts.map(certKernel).join(" and ")} denied it while ${allowingCerts.map(certKernel).join(" and ")} allowed it; the BLOCK headline comes from ${denyKernel}.`
      : "") +
    (contradiction ? ` ${contradiction}` : "");

  return [
    {
      label: "What was asked",
      text: `The receipt says the tool was ${valueOrAbsent(r, "tool")} with arguments ${present(r, "arguments") ? readableJson(r.arguments) : "absent"}.`,
      fields: ["tool", "arguments"],
    },
    {
      label: "What was decided, and by whom",
      text: decision,
      fields: ["verdict", "deny_kernel", "certs[].kernel", "certs[].verdict"],
    },
    {
      label: "What the receipt binds",
      text: `canonical_request_sha256 is ${valueOrAbsent(r, "canonical_request_sha256")}; args_hash is ${valueOrAbsent(r, "args_hash")}. Those are the request-hash fields this receipt records for the call and its arguments.`,
      fields: ["canonical_request_sha256", "args_hash"],
    },
    {
      label: "Time base",
      text: present(r, "now")
        ? r.now === 1000
          ? "now is 1000. The receipt records that exact logical time value."
          : `now is ${readableJson(r.now)}. The receipt records that exact logical time value.`
        : "now is absent. The receipt provides no logical time value.",
      fields: ["now"],
    },
    {
      label: "Mediation",
      text: present(r, "bypass")
        ? r.bypass === false
          ? "bypass is false: the receipt records that mediation was not skipped."
          : r.bypass === true
            ? "bypass is true: the receipt records that mediation was skipped."
            : `bypass is ${readableJson(r.bypass)}: the receipt does not provide a boolean mediation status.`
        : "bypass is absent. The receipt does not state whether mediation was skipped.",
      fields: ["bypass"],
    },
    {
      label: "What this receipt does not say",
      text: `kernel_identity.wasm_sha256 is ${pathValueOrAbsent(r, ["kernel_identity", "wasm_sha256"])}. It names the kernel hash recorded in this receipt. ${KERNEL_HASH_SCOPE_LIMIT_TEXT}`,
      fields: ["kernel_identity.wasm_sha256"],
    },
  ];
}

export function clearReceiptSummary(container) {
  if (!container) return;
  container.replaceChildren();
}

export function renderReceiptSummary(container, receipt) {
  if (!container) return;
  clearReceiptSummary(container);
  const doc = container.ownerDocument || document;
  for (const entry of receiptSummaryEntries(receipt)) {
    const row = doc.createElement("p");
    row.className = "receipt-summary-line";
    const label = doc.createElement("strong");
    label.textContent = entry.label + ": ";
    row.append(label, doc.createTextNode(entry.text));
    container.append(row);
  }
}
