// SPDX-License-Identifier: Apache-2.0
// Plain-language, field-for-field receipt summary shared by both browser pages.
// This module deliberately does not parse, validate, canonicalize, or hash a
// receipt. Those jobs remain in receipt-format.js and receipt.js.
import { KERNEL_HASH_SCOPE_LIMIT_TEXT } from "./page-claims.js";
import { createTooltip } from "./tooltip.js";

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

  // Any denying gate makes the combined decision BLOCK; otherwise the
  // determinate gates allow. Mixed allow/deny results are ordinary BLOCKs.
  const combined = denyingCerts.length ? "BLOCK" : determinateCerts.length ? "ALLOW" : null;
  if ((headline === "ALLOW" || headline === "BLOCK") && combined !== null && headline !== combined) {
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

// Compact value per row, built only from the same fields the entry's own
// `fields` list already names — this restates them short for the table cell.
// receiptSummaryEntries()'s own `text` sentence is unchanged (byte for byte)
// and becomes that row's tooltip; nothing here recomputes a verification
// result, it only re-states already-computed fields for a narrower cell.
function compactSummaryValue(receipt, entry) {
  const r = receipt || {};
  switch (entry.label) {
    case "What was asked":
      return `${valueOrAbsent(r, "tool")} ${present(r, "arguments") ? readableJson(r.arguments) : "absent"}`;
    case "What was decided, and by whom": {
      const certs = Array.isArray(r.certs) ? r.certs : null;
      const gateText = certs === null ? "certs absent"
        : certs.length ? certs.map((c) => `${certKernel(c)} ${present(c, "verdict") ? String(c.verdict) : "no verdict"}`).join(" · ")
          : "certs: empty array";
      return `${gateText} · deny_kernel ${valueOrAbsent(r, "deny_kernel")}`;
    }
    case "What the receipt binds":
      return `canonical_request_sha256 ${valueOrAbsent(r, "canonical_request_sha256")}  ·  args_hash ${valueOrAbsent(r, "args_hash")}`;
    case "Time base":
      return present(r, "now") ? `now = ${readableJson(r.now)}` : "now: absent";
    case "Mediation":
      return present(r, "bypass") ? `bypass = ${readableJson(r.bypass)}` : "bypass: absent";
    case "What this receipt does not say":
      return `kernel_identity.wasm_sha256 = ${pathValueOrAbsent(r, ["kernel_identity", "wasm_sha256"])}`;
    default:
      return entry.text;
  }
}

// One <tr> per entry: [th label, td value, td "recorded", td tooltip-trigger].
// The test harness's fake document builds these rows too (with a minimal
// FakeNode that has no innerHTML), so every assignment here is textContent —
// never innerHTML — and every element comes from doc.createElement, never a
// bare global `document`.
export function renderReceiptSummary(container, receipt) {
  if (!container) return;
  clearReceiptSummary(container);
  const doc = container.ownerDocument || document;
  let i = 0;
  for (const entry of receiptSummaryEntries(receipt)) {
    i += 1;
    const tr = doc.createElement("tr");
    const label = doc.createElement("th");
    label.textContent = entry.label;
    const value = doc.createElement("td");
    value.textContent = compactSummaryValue(receipt, entry);
    if (entry.label === "What was decided, and by whom" && /CONFLICT:|split decision/.test(entry.text)) {
      const flag = doc.createElement("strong");
      flag.className = "rvt-fail";
      flag.textContent = entry.text.includes("CONFLICT:") ? " CONFLICT — see ⓘ" : " split decision — see ⓘ";
      value.append(flag);
    }
    const state = doc.createElement("td");
    state.className = "muted rvt-state";
    state.textContent = "recorded";
    const tipCell = doc.createElement("td");
    tipCell.append(createTooltip(doc, entry.label, entry.text, { id: `tip-summary-${i}` }));
    tr.append(label, value, state, tipCell);
    container.append(tr);
  }
}
