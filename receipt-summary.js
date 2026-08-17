// SPDX-License-Identifier: Apache-2.0
// Plain-language, field-for-field receipt summary shared by both browser pages.
// This module deliberately does not parse, validate, canonicalize, or hash a
// receipt. Those jobs remain in receipt-format.js and receipt.js.

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
  const decision = `The receipt states ${headline}; deny_kernel is ${denyKernel}. Per-gate results: ${certText}.` +
    (split
      ? ` This is a split decision: ${denyingCerts.map(certKernel).join(" and ")} denied it while ${allowingCerts.map(certKernel).join(" and ")} allowed it; the BLOCK headline comes from ${denyKernel}.`
      : "");

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
      text: `canonical_request_sha256 is ${valueOrAbsent(r, "canonical_request_sha256")}; args_hash is ${valueOrAbsent(r, "args_hash")}. These are the receipt's fingerprints for this call and its arguments, so the receipt identifies this call rather than another one.`,
      fields: ["canonical_request_sha256", "args_hash"],
    },
    {
      label: "Time base",
      text: present(r, "now")
        ? r.now === 1000
          ? "now is 1000. This is a fixed synthetic clock, not a wall-clock timestamp."
          : `now is ${readableJson(r.now)}. This is the receipt's logical time value; it is not, by itself, a wall-clock timestamp.`
        : "now is absent. The receipt provides no time-base value.",
      fields: ["now"],
    },
    {
      label: "Mediation",
      text: present(r, "bypass")
        ? r.bypass === false
          ? "bypass is false: the receipt says mediation was not skipped, so a kernel decision is recorded."
          : r.bypass === true
            ? "bypass is true: the receipt says mediation was deliberately skipped, so it records no kernel decision."
            : `bypass is ${readableJson(r.bypass)}: the receipt does not provide a boolean mediation status.`
        : "bypass is absent. The receipt does not state whether mediation was skipped.",
      fields: ["bypass"],
    },
    {
      label: "What this receipt does not say",
      text: "It does not certify your whole MCP server, your transport, your tool implementations, or that your deployment actually routes calls through this gate. The sha256 verifies which binary ran.",
      fields: ["kernel_identity.wasm_sha256"],
    },
  ];
}

export function renderReceiptSummary(container, receipt) {
  if (!container) return;
  container.replaceChildren();
  for (const entry of receiptSummaryEntries(receipt)) {
    const row = document.createElement("p");
    row.className = "receipt-summary-line";
    const label = document.createElement("strong");
    label.textContent = entry.label + ": ";
    row.append(label, document.createTextNode(entry.text));
    container.append(row);
  }
}
