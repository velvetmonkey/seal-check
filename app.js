// SPDX-License-Identifier: Apache-2.0
// seal-check UI wiring. No kernel logic — it re-checks receipts client-side.
import {
  ready, verifyKernelSha,
} from "./kernel.js";
import { b64urlToStr, verifyReceipt, callSummary } from "./receipt.js";
import { classifyReceiptDocument } from "./receipt-format.js";
import { classifyReceiptFragment } from "./fragment-classifier.js";
import { renderPageClaims } from "./page-claims.js";
import { pastedReceiptDocumentOrError } from "./receipt-input.js";
import { clearReceiptSummary, renderReceiptSummary } from "./receipt-summary.js";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

let SHA = null;       // {computed, pinned, match}
let LOCKED = false;   // true if kernel mismatch — refuse to emit receipts
const BUNDLED_EXAMPLE_RECEIPT = new URL("examples/allow.receipt.json", import.meta.url);

// --- kernel boot + self-verification ----------------------------------------
async function boot() {
  const pill = $("kernel-status");
  // file:// blocks both the wasm fetch and SubtleCrypto. Tell the user the fix up front.
  if (location.protocol === "file:") {
    LOCKED = true;
    pill.className = "pill pill-bad";
    pill.textContent = "open over http, not file:// — run  python3 -m http.server 8000  then visit http://localhost:8000";
    return;
  }
  try {
    SHA = await verifyKernelSha();
    $("ident-sha").textContent = SHA.computed;
    if (SHA.match) {
      pill.className = "pill pill-ok";
      pill.textContent = `kernel verified · sha256 ${SHA.computed.slice(0, 8)}…`;
      await ready();
      if ($("paste-input")) await renderLocationReceiptOrExample();
    } else {
      LOCKED = true;
      pill.className = "pill pill-bad";
      pill.textContent = "KERNEL MISMATCH — binary does not match the pinned sha256; receipts disabled";
    }
  } catch (e) {
    LOCKED = true;
    pill.className = "pill pill-bad";
    pill.textContent = "kernel could not be verified: " + e.message;
  }
}

// --- deep-linked receipt verification (opened via #receipt=...) --------------
function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function rvLine(okFlag, text) {
  const li = el("li", "rv-" + (okFlag === true ? "ok" : okFlag === false ? "bad" : "skip"));
  li.textContent = (okFlag === true ? "✓ " : okFlag === false ? "✗ " : "• ") + text;
  return li;
}
// The large first-screen verdict of the re-check. Presentation only: it renders
// an outcome that verifyReceipt already computed; nothing is decided here.
function paintBanner(state, headline, subline, failItems) {
  const banner = $("rv-banner");
  banner.className = "rv-banner " + state;
  $("rv-headline").textContent =
    (state === "ok" ? "✓ " : state === "bad" ? "✗ " : "! ") + headline;
  $("rv-subline").textContent = subline;
  const ul = $("rv-fails");
  ul.textContent = "";
  if (failItems && failItems.length) {
    for (const t of failItems) ul.append(el("li", null, t));
    ul.classList.remove("hidden");
  } else {
    ul.classList.add("hidden");
  }
}
// Plain-language restatement of checks that FAILED, read from fields
// verifyReceipt has already computed. Strict === false tests only: null and
// undefined mean "not applicable", never a failure.
function plainFailures(r) {
  const f = [];
  if (r.formatOk === false) f.push("the receipt does not have the shape a real receipt must have (schema validation failed)");
  if (r.kernelShaMatch === false) f.push("the decision software named in the receipt is not the verified kernel this page runs");
  if (r.requestHashMatch === false) f.push("the request written in the receipt no longer matches the receipt's own fingerprint of it");
  if (r.bindingOk === false) f.push("the policy displayed in the receipt does not match the policy bytes that were signed");
  if (r.grantErrors && r.grantErrors.length > 0) f.push("the receipt's approval grants could not be resolved against its signed policy");
  if (r.signature_valid === false && r.signature_status !== "crypto_unavailable") f.push("the signature does not match the receipt — something changed after it was signed");
  if (r.verdictMatch === false) f.push(`re-running the same request through the same kernel gives a different decision (${r.rederived === "BLOCK" ? "REFUSED" : r.rederived}) than the receipt claims`);
  if (r.emittedBytesMatch === false) f.push("the kernel's recorded output bytes differ from the re-run");
  if (r.kernelMaterialConsistent === false) f.push("the kernel material inside the receipt disagrees with itself");
  if (r.kernelRequestBinding === false) f.push("the kernel's own record of what it judged does not match the request the receipt claims");
  if (r.authority_trusted === false) f.push("the receipt is signed by a key this deployment does not accept as the operator's");
  if (f.length === 0) f.push("open the technical view below for the exact comparison that failed");
  return f;
}
// Three-state comparison table. Every row is exactly one of: checked-passed,
// checked-FAILED, or NOT CHECKED with the reason and what WOULD check it.
// Presentation only — every cell restates a field verifyReceipt computed. The
// last rows are NOT CHECKED in every state, on purpose: this table must never
// be able to render all green, and authority never renders as a green tick.
function renderCheckTable(r, receipt) {
  const tbl = $("rv-table");
  const tb = tbl.querySelector("tbody");
  tb.replaceChildren();
  const row = (what, state, detail) => {
    const tr = el("tr", state === "fail" ? "rvt-row-fail" : null);
    const stateText = state === "pass" ? "✓ checked — passed"
      : state === "fail" ? "✗ checked — FAILED" : "— NOT CHECKED";
    tr.append(el("td", null, what), el("td", "rvt-state rvt-" + state, stateText),
      el("td", "rvt-detail", detail));
    tb.append(tr);
  };
  const sha12 = (s) => (typeof s === "string" ? s.slice(0, 12) + "…" : "?");

  // decision software
  if (r.kernelShaMatch === true) row("Decision software (kernel)", "pass",
    `the binary that decided is the audited kernel this page self-verified (sha256 ${sha12(r.kernelSha)})`);
  else row("Decision software (kernel)", "fail",
    "the receipt names a different kernel binary than the one this page verified");

  // the request
  if (r.requestHashMatch === true) row("The request", "pass",
    `the request text matches the receipt's own fingerprint (${sha12(receipt.canonical_request_sha256)})`);
  else if (r.requestHashMatch === false) row("The request", "fail",
    "the request written in the receipt no longer matches the receipt's own fingerprint of it");
  else row("The request", "skip",
    r.unparseableRequest
      ? "the original wire line could not be re-parsed, so no canonical re-derivation is possible; the raw line hash (request_sha256) is the only request identity carried. A receipt with a parseable request would check this."
      : "no request comparison ran for this receipt");

  // policy binding
  if (r.bindingOk === true) row("Policy binding", "pass",
    "the policy displayed in the receipt byte-equals the policy bytes that were signed");
  else if (r.bindingOk === false) row("Policy binding", "fail",
    (r.bindingErrors || []).join("; ") || "the displayed policy does not match the signed bytes");
  else row("Policy binding", "skip", "binding was not evaluated for this receipt");

  // signature — surfaces WHICH verifier ran (WebCrypto or the vendored TweetNaCl)
  const sigAttempted = r.bindingOk === true && (r.grantErrors || []).length === 0;
  if (!sigAttempted) row("Signature", "skip",
    "not reached — the signature is verified over the signed policy bytes, and an earlier check failed first; fixing it would let this run");
  else if (r.signature_valid === true) row("Signature", "pass",
    `valid — verified by ${r.signature_verifier === "tweetnacl" ? "the shipped TweetNaCl verifier (WebCrypto had no Ed25519 here)" : r.signature_verifier === "webcrypto" ? "WebCrypto Ed25519" : "the kernel's own config check"}. A valid signature shows the receipt is exactly what Seal on that machine signed and has not changed since. It does NOT show the decision it describes actually happened — see the last rows.`);
  else if (r.signature_status === "crypto_unavailable") row("Signature", "skip",
    `${r.cryptoUnavailableReason || "no Ed25519 verifier was available"}. Opening this page over https (or any context with a verifier) would check it.`);
  else row("Signature", "fail",
    "the signature does not verify — the receipt is not what was signed");

  // decision replay
  if (r.verdictMatch === true) row("Decision replay", "pass",
    `re-ran the exact request through the kernel on your device: same decision (${r.rederived === "BLOCK" ? "REFUSED" : r.rederived})`);
  else if (r.verdictMatch === false) row("Decision replay", "fail",
    `re-running the same request gives a different decision (${r.rederived === "BLOCK" ? "REFUSED" : r.rederived}) than the receipt claims`);
  else row("Decision replay", "skip",
    r.unparseableRequest
      ? "an unparseable-request receipt carries no (tool, arguments) to replay; a parseable request would check it"
      : r.rederiveError
        ? `not reached — ${r.rederiveError}; a receipt passing the earlier checks would let the replay run`
        : "this receipt carries nothing to replay against");

  // emitted bytes
  if (r.emittedBytesMatch === true) row("Decision output bytes", "pass",
    "the kernel's emitted bytes are byte-identical to the re-run");
  else if (r.emittedBytesMatch === false) row("Decision output bytes", "fail",
    "the kernel's recorded output bytes differ from the re-run");
  else row("Decision output bytes", "skip",
    "not reached — the replay did not run, so there is nothing to compare the recorded bytes against");

  // kernel's own request commitment
  if (r.kernelRequestBinding === true) row("Kernel's request commitment", "pass",
    "the kernel's own hash of the bytes it judged matches the request this receipt claims");
  else if (r.kernelRequestBinding === false) row("Kernel's request commitment", "fail",
    "the kernel's own record of what it judged does not match the request the receipt claims");
  else row("Kernel's request commitment", "skip",
    "not reached — depends on the kernel material checks above");

  // kernel material consistency (only meaningful on unparseable receipts)
  if (r.kernelMaterialConsistent === true) row("Kernel material consistency", "pass",
    "the audit embedded in emitted_bytes names the same verdict and certs the receipt asserts");
  else if (r.kernelMaterialConsistent === false) row("Kernel material consistency", "fail",
    "the kernel material inside the receipt disagrees with itself");

  // received document bytes
  if (r.document_checked === true) row("Received document bytes", "pass",
    "the raw received text was validated, including the wire ambiguities JSON parsing collapses");
  else row("Received document bytes", "skip",
    "this record was handed over as an already-parsed object (it was minted in this page), so no received bytes exist to examine. Opening it from a #receipt= link would check them.");

  // authority — NEVER a green tick (Ben's ruling): unpinned is NOT CHECKED.
  if (r.authority_trusted === false) row("Who signed it (authority)", "fail",
    "the receipt is signed by a key this deployment was told not to accept as the operator's");
  else if (r.authority_trusted === true) row("Who signed it (authority)", "skip",
    "checked against a supplied operator pin and it matches — but browser deployments normally pin nothing, so treat authority as established out-of-band, not here");
  else row("Who signed it (authority)", "skip",
    `no operator key is pinned in this deployment. Comparing the signing key (${receipt && receipt.signed_config && receipt.signed_config.pubkey ? receipt.signed_config.pubkey : "unknown"}) with the key your operator publishes, out-of-band, would check it.`);

  // permanently out of scope — these rows keep the table honest in every state
  row("That the decision actually happened", "skip",
    "this page cannot see the system that produced the receipt: it cannot tell whether the request was really routed through the gate, or what happened after. Only that system's own records could check this.");
  row("That approved targets deserved approval", "skip",
    "by design — approval targets travel as opaque commitments (fire-your-own-target), so this page does not check that they point at anything the operator's policy authorized. Only an audit of the operator's policy could check what they bind to.");

  tbl.classList.remove("hidden");
}
// Receipt scenario: focus the page on the receipt while keeping the claims visible.
function focusReceiptMode() {
  $("receipt-verify").classList.remove("hidden");
  const tag = document.querySelector("header .tag");
  if (tag) tag.classList.add("hidden");
  // Compact the header without hiding any of the page's claims or limits.
  document.body.classList.add("receipt-mode");
}
function showReceiptError(msg, focus = true, { isExample = false } = {}) {
  paintReceiptState(isExample);
  if (focus) focusReceiptMode();
  $("rv-result").classList.remove("hidden");
  paintBanner("bad", "This receipt could not be read", msg);
  $("rv-table").classList.add("hidden");
  const s = $("rv-summary"); s.textContent = msg; s.className = "reason bad";
  $("rv-tech").open = true;
}

// The marker is painted by every receipt/error render from that render's own
// state. It cannot survive a visitor result merely because an example painted
// it earlier.
function paintReceiptState(isExample) {
  clearReceiptSummary($("receipt-summary"));
  $("rv-example-label")?.remove();
  // Result content belongs to the state that created it. Clearing every
  // mutable field at the boundary means an error can never retain an earlier
  // example's rows, raw JSON, checks, or narrative while merely hiding part of
  // the result.
  $("rv-table").querySelector("tbody").replaceChildren();
  for (const id of ["rv-context", "rv-verdict", "rv-deny", "rv-checks", "rv-json", "rv-summary"])
    $(id).replaceChildren();
  if (isExample) {
    const label = el("p", "example-label");
    label.id = "rv-example-label";
    label.append(el("strong", null, "EXAMPLE RECEIPT"),
      " — bundled sample, not a receipt supplied by you. Its checks below apply only to this example.");
    $("rv-result").prepend(label);
  }
}

// Back to the bare page: box empty, nothing result-shaped on screen.
function hideReceiptResult() {
  paintReceiptState(false);
  $("rv-banner").className = "rv-banner hidden";
  $("rv-result").classList.add("hidden");
}

// HTML fragment describing the mediated call — demo receipts keep their
// operation-on-table phrasing, everything else falls back to tool+arguments.
function appendCallSummary(container, receipt) {
  const s = callSummary(receipt);
  if (s.unparseable) {
    container.append("make a call whose wire line could not be re-parsed by the receipt layer (§11.1; raw line sha256 ");
    container.append(el("code", null, s.rawLineShort));
    container.append(")");
    return;
  }
  if (s.demo) {
    container.append("run ", el("code", null, s.operation), " on ", el("code", null, s.table));
    return;
  }
  container.append("call ", el("code", null, s.tool), " with arguments ", el("code", null, s.argsJson));
}

function appendReceiptClaimNote(container) {
  container.append(" ", el("em", "muted", "(as the receipt claims — not confirmed by this page)"));
}

// The control receipt: seal was switched OFF (bypass), so there is no kernel
// decision to verify. Render it honestly, NOT as a passed verification.
function renderControlReceipt(receipt, { isExample = false } = {}) {
  paintReceiptState(isExample);
  renderReceiptSummary($("receipt-summary"), receipt);
  const ex0 = receipt.execution || {};
  paintBanner("bad", "No gate stood here",
    "This is the control receipt: the seal gate was switched OFF for this run, so nothing decided anything. " +
    (ex0.executed
      ? `The same request the gate refuses went straight through, and ${ex0.rows_affected} rows were destroyed. `
      : "The same request the gate refuses went straight through. ") +
    "This record exists to show what happens without the gate.");
  $("rv-result").classList.remove("hidden");
  $("rv-table").classList.add("hidden");
  $("rv-tech").open = true;
  const verdictNode = $("rv-verdict");
  verdictNode.textContent = "NO GATE";
  verdictNode.className = "verdict v-block";
  $("rv-deny").textContent = "seal switched off (control)";
  const context = $("rv-context");
  context.append("This is the ", el("strong", null, "control"), " run. The gate was switched OFF, so it did not mediate the call. The agent asked to ");
  appendCallSummary(context, receipt);
  context.append(" — with the gate absent, nothing stood in the way.");
  const ul = $("rv-checks"); ul.textContent = "";
  ul.append(rvLine(true, `request bytes match the receipt's fingerprint (${(receipt.canonical_request_sha256 || "").slice(0, 12)}…), the same request as the blocked attack`));
  ul.append(rvLine(null, "the gate was OFF, so the verified kernel did NOT run, nothing mediated this call"));
  const ex = receipt.execution || {};
  ul.append(rvLine(false, ex.executed ? `result: the delete EXECUTED, ${ex.rows_affected} rows destroyed` : "result: no execution recorded"));
  $("rv-json").textContent = JSON.stringify(receipt, null, 2);
  const s = $("rv-summary");
  s.textContent = "Without the gate, the identical attack succeeded and the data was destroyed. That is exactly what the gate prevents.";
  s.className = "reason bad";
  $("receipt-verify").scrollIntoView({ behavior: "smooth", block: "start" });
}
// `input` is the received receipt DOCUMENT (raw JSON text) for anything that
// arrived from a link, or a minted receipt object for the local demo. §12.6:
// the text form is the one that can be checked against the bytes.
async function renderVerifiedReceipt(input, {
  focus = true, scroll = true, isExample = false, isCurrent = () => true,
} = {}) {
  paintReceiptState(isExample);
  if (focus) focusReceiptMode();
  $("rv-tech").open = false; // re-opened below for states that demand a close look
  let r;
  try { r = await verifyReceipt(input); } catch (e) {
    if (isCurrent()) return showReceiptError("verification error: " + e.message, focus, { isExample });
    return;
  }
  if (!isCurrent()) return;
  const receipt = r.receipt;
  if (!receipt) {
    return showReceiptError("receipt failed schema validation: " +
      (r.formatErrors || []).join("; "), focus, { isExample });
  }

  if (receipt.bypass) return renderControlReceipt(receipt, { isExample });
  if (r.formatOk === false) {
    return showReceiptError("receipt failed schema validation (" + (r.formatVersion || "unrecognized") + "): " +
      (r.formatErrors || []).join("; "), focus, { isExample });
  }
  renderReceiptSummary($("receipt-summary"), receipt);
  $("rv-result").classList.remove("hidden");
  const verdictNode = $("rv-verdict");
  verdictNode.textContent = receipt.verdict === "BLOCK" ? "REFUSED" : receipt.verdict === "ALLOW" ? "ALLOWED" : (receipt.verdict || "?");
  verdictNode.className = "verdict " + (receipt.verdict === "BLOCK" ? "v-block" : receipt.verdict === "ALLOW" ? "v-allow" : "v-error");
  $("rv-deny").textContent = receipt.deny_kernel ? `${receipt.deny_kernel} rule` : "";

  const context = $("rv-context");
  context.append("What this receipt records: an AI agent asked to ");
  appendCallSummary(context, receipt);
  context.append(", and the seal gate — safety software standing between the agent and the thing it wanted to touch — decided. The decision on record:");

  const ul = $("rv-checks"); ul.textContent = "";
  // §12.6: say plainly whether the RECEIVED BYTES were checked, or whether
  // this is a locally minted object with no wire document behind it. The
  // difference is what a duplicate discriminator hides in.
  if (!r.document_checked) {
    ul.append(rvLine(null, "receipt document not checked: this record was minted in this page, so there are no received bytes to check for a repeated version discriminator"));
  }
  ul.append(rvLine(r.kernelShaMatch, `kernel binary self-verified (sha256 ${r.kernelSha.slice(0, 12)}…, matches the receipt)`));
  if (r.unparseableRequest) {
    // §11.1: not a match, not a mismatch — its own state, named calmly.
    ul.append(rvLine(null, `request identity is the raw wire line only (request_sha256 ${(receipt.request_sha256 || "").slice(0, 12)}…) — the line could not be re-parsed (${receipt.request_parse_error}), so no canonical re-derivation is possible`));
  } else {
    ul.append(rvLine(r.requestHashMatch, `request bytes match the receipt's fingerprint (${(receipt.canonical_request_sha256 || "").slice(0, 12)}…)`));
  }
  ul.append(rvLine(r.bindingOk, r.bindingOk
    ? "signed config bytes bind exactly to the displayed kernel_config"
    : `signed config binding failed: ${(r.bindingErrors || []).join("; ")}`));
  ul.append(rvLine(r.signature_valid, r.signature_valid
    ? `signature_valid: signed by holder of ${receipt.signed_config.pubkey.slice(0, 12)}…` +
      (r.signature_verifier === "tweetnacl"
        ? ` (verified by the shipped TweetNaCl fallback; WebCrypto ${r.webcrypto_status === "absent" ? "was absent" : "did not support Ed25519"})`
        : "")
    : r.signature_status === "crypto_unavailable"
      ? `REFUSED crypto_unavailable: ${r.cryptoUnavailableReason}`
      : "signature_invalid: the signature does not verify"));
  if (r.unparseableRequest) {
    ul.append(rvLine(null, "verdict not re-derivable: an unparseable-request receipt carries no (tool, arguments) to replay"));
    ul.append(rvLine(r.kernelMaterialConsistent, r.kernelMaterialConsistent
      ? "kernel material self-consistent: emitted_bytes audit names the receipt's own verdict and certs (consistency, not replay)"
      : "kernel material inconsistent: emitted_bytes audit disagrees with the receipt's verdict or certs"));
  } else if (r.verdictMatch === null) {
    ul.append(rvLine(null, receipt.bypass ? "verdict not re-derivable: this receipt had the gate switched OFF (the control)" : "verdict not re-derivable (receipt carries no policy)"));
  } else {
    ul.append(rvLine(r.verdictMatch, `verdict reproduced on-device: ${r.rederived === "BLOCK" ? "REFUSED" : r.rederived} (re-ran the exact request through the kernel)`));
  }
  if (r.emittedBytesMatch !== null && r.emittedBytesMatch !== undefined) {
    ul.append(rvLine(r.emittedBytesMatch, "emitted decision bytes byte-identical to the re-run"));
  }
  if (!r.unparseableRequest) {
    ul.append(rvLine(r.kernel_replay_consistent, `kernel_replay_consistent: ${r.kernel_replay_consistent}`));
  }
  const freshness = r.config_freshness;
  if (freshness) ul.append(rvLine(null,
    `config freshness carried: ${freshness.field}=${freshness.value}; rollback enforcement=${freshness.rollback_enforced}`));
  ul.append(rvLine(r.authority_trusted === true ? true : r.authority_trusted === false ? false : null,
    r.authority_trusted === true
      ? "authority_trusted: pinned operator key"
      : r.authority_trusted === "unpinned"
        ? `authority_trusted: UNPINNED — verify ${receipt.signed_config.pubkey} out-of-band`
        : "authority_trusted: false"));
  // Neutral disclosure, not a warning: opaque commitments are how this
  // fire-your-own-target box works, so the boundary is named, calmly.
  if (r.hasOpaqueGrants) {
    ul.append(rvLine(null, `${r.opaqueGrants} capability grant(s) carried as opaque target commitments — expected for this fire-your-own-target box. seal-check verifies the decision, not what the grants bind to.`));
  }

  $("rv-json").textContent = JSON.stringify(receipt, null, 2);
  const s = $("rv-summary");
  if (r.outcome === "authorised") {
    s.textContent = "AUTHORISED: signed by pinned operator key.";
    s.className = "reason ok";
  } else if (r.outcome === "authorised-unparseable") {
    s.textContent = "REDUCED SCOPE (authorised-unparseable): signed by pinned operator key; the wire line could not be re-parsed, so no independent replay was performed — NOT independently verified. The verdict rests on the kernel material carried.";
    s.className = "reason warn";
  } else if (r.outcome === "unpinned") {
    s.textContent = `AUTHENTIC + REPLAY-CONSISTENT, authority NOT established (signed by ${receipt.signed_config.pubkey}, verify it out-of-band).`;
    s.className = "reason warn";
  } else if (r.outcome === "unverified-document") {
    // §12.6: object-path ceiling. Every local check passed, but no received
    // bytes were examined — expected (and honest) for a record minted in this
    // page; never a verified wire receipt.
    s.textContent = "LOCAL OBJECT (unverified-document): every local check passed, but this record was handed to the verifier as an already-parsed object, so no received document bytes were examined. That is expected for a receipt minted in this page. Anything that arrived from outside must be verified as its raw text.";
    s.className = "reason warn";
  } else if (r.outcome === "crypto_unavailable") {
    s.textContent = `REFUSED crypto_unavailable: ${r.cryptoUnavailableReason}`;
    s.className = "reason bad";
  } else {
    s.textContent = "One or more checks did not pass. Treat this receipt with suspicion.";
    s.className = "reason bad";
  }

  // First-screen banner: the same outcome verifyReceipt computed, said large
  // and in plain words. The limits stated here must not shrink — signer
  // identity and document scope included.
  const pub12 = receipt.signed_config && typeof receipt.signed_config.pubkey === "string"
    ? receipt.signed_config.pubkey.slice(0, 12) + "…" : "an unknown key";
  if (r.outcome === "authorised") {
    paintBanner("ok", "This receipt checks out",
      "Re-checked on your device just now: the request matches its fingerprint, the same verified kernel re-derives the same decision byte for byte, and it is signed by the pinned operator key.",
      null);
  } else if (r.outcome === "authorised-unparseable") {
    paintBanner("warn", "Signed and intact — but only partly re-checkable",
      "The signature is valid (pinned operator key) and everything the receipt carries verifies, but the original request line could not be re-parsed, so this page could not independently re-run the decision. The verdict rests on the kernel material the receipt carries, not on an independent replay.",
      null);
  } else if (r.outcome === "unpinned") {
    paintBanner("warn", "Intact — but the signer is not verified",
      `Every content check passed: the request matches its fingerprint, the same verified kernel re-derives the same decision byte for byte, and the signature is valid. What this page cannot establish is who holds the signing key (${pub12}) — no operator key is pinned in this deployment, so confirm that key out-of-band before treating this as your operator's receipt.`,
      null);
  } else if (r.outcome === "unverified-document") {
    paintBanner("warn", "All local checks passed — but this is not a verified document",
      "This record was minted inside this page a moment ago, so there are no received bytes to examine. Anything that arrives from outside — a link, a file — is verified as its raw text; a record handed over as an already-parsed object can never rank higher than this.",
      null);
  } else if (r.outcome === "crypto_unavailable") {
    paintBanner("bad", "Could not check the signature",
      `${r.cryptoUnavailableReason || "No signature verifier is available in this browser."} Without a signature check this receipt cannot be called verified.`,
      null);
    appendReceiptClaimNote(context);
    $("rv-tech").open = true;
  } else {
    paintBanner("bad", "This receipt does NOT check out",
      "At least one re-check failed on your device, so what this receipt says cannot be trusted. Treat it with suspicion. What does not line up:",
      plainFailures(r));
    appendReceiptClaimNote(context);
    $("rv-tech").open = true;
  }

  renderCheckTable(r, receipt);
  if (scroll) $("receipt-verify").scrollIntoView({ behavior: "smooth", block: "start" });
}

// Feed the bundled document into the paste handler.  The example therefore
// takes the same raw-document parsing, classification, and verification route
// as a receipt the visitor pasted.
async function renderBundledExampleReceipt(isCurrent = () => true, { scroll = true } = {}) {
  let document;
  try {
    const response = await fetch(BUNDLED_EXAMPLE_RECEIPT);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    document = await response.text();
  } catch (e) {
    if (isCurrent()) return showReceiptError("example receipt could not be loaded: " + e.message, true, { isExample: true });
    return;
  }
  if (!isCurrent()) return;
  bundledExampleDocument = document.trim();
  $("paste-input").value = document;
  return renderClassifiedReceiptDocument(document, { isExample: true, isCurrent, scroll });
}

let locationRenderVersion = 0;
let bundledExampleDocument = null;

// Fragments that name a section of this page are navigation, not receipts.
const NAV_ANCHOR_IDS = ["receipt-verify", "claims"];
function navAnchorTarget(hash) {
  const id = hash.startsWith("#") ? hash.slice(1) : hash;
  return NAV_ANCHOR_IDS.includes(id) ? document.getElementById(id) : null;
}

// Initial loads and live fragment changes take this same total route. The
// generation guard prevents an older async verification or example fetch from
// repainting after a newer fragment has become current.
async function renderLocationReceiptOrExample() {
  const version = ++locationRenderVersion;
  const isCurrent = () => version === locationRenderVersion;

  // Navigation anchors: the browser scrolls to the section natively. A closed
  // fold is opened so the link lands on content, and the page renders its
  // bare-page state (the bundled example) without stealing the scroll.
  const nav = navAnchorTarget(location.hash);
  if (nav) {
    paintReceiptState(false);
    if (nav.tagName === "DETAILS") nav.open = true;
    return renderBundledExampleReceipt(isCurrent, { scroll: false });
  }

  const state = classifyReceiptFragment(location.hash);

  // Remove prior example-owned DOM synchronously, before any async work.
  paintReceiptState(false);
  if (state.kind === "absent") return renderBundledExampleReceipt(isCurrent);
  $("paste-input").value = state.document ?? "";
  if (state.kind === "empty" || state.kind === "whitespace-only" || state.kind === "unparseable")
    return showReceiptError(state.error);

  // Both remaining cases carry decoded visitor bytes. The document router
  // gives wrong-shape inputs their family-specific refusal and valid receipt
  // documents the normal verifier result.
  return renderClassifiedReceiptDocument(state.document, { isCurrent });
}

// Route every received document the same way, regardless of whether it arrived
// in a deep link or through the paste box.  A Spine receipt must never fall
// through to the decision-receipt verifier merely because its transport changed.
function renderClassifiedReceiptDocument(document_, { isExample = false, isCurrent = () => true, scroll = true } = {}) {
  if (!isCurrent()) return;
  // The raw text, not a parsed object: the link's own bytes decide both its
  // family and whether a duplicate/escaped discriminator hid that family.
  const classified = classifyReceiptDocument(document_);
  if (classified.family === "malformed")
    return showReceiptError("receipt document refused: " + classified.errors.join("; "), true, { isExample });
  if (classified.family === "decision") return renderVerifiedReceipt(document_, { isExample, isCurrent, scroll });
  if (classified.family === "spine") return showReceiptError(
    "This is a seal.spine/v1 proxy receipt, not the kernel decision-receipt format this page checks. " +
    "It is refused here rather than being treated as a decision receipt. Use the shipped Spine checker with the signer public key obtained out of band: " +
    "node checker/seal-receipt-check.mjs RECEIPT.json --pubkey OUT_OF_BAND_PUBKEY.", true, { isExample },
  );
  if (classified.family === "ambiguous")
    return showReceiptError("receipt refused: it claims both a kernel decision-receipt format and the distinct seal.spine/v1 proxy format. A record must have exactly one receipt kind.", true, { isExample });
  if (classified.family === "unknown_format")
    return showReceiptError(`receipt refused: unsupported receipt discriminator ${JSON.stringify(classified.format)}. This page verifies kernel decision receipts; seal.spine/v1 proxy receipts use the separate Spine checker.`, true, { isExample });
  return showReceiptError("receipt refused: no recognized receipt discriminator. This page verifies kernel decision receipts; seal.spine/v1 proxy receipts use the separate Spine checker.", true, { isExample });
}

// --- pasted receipt ----------------------------------------------------------
// The paste box accepts a receipt in any form it travels: the raw JSON
// document, a full link carrying #receipt=<base64url>, or the bare base64url
// blob. Everything is reduced to the received DOCUMENT TEXT before it reaches
// verifyReceipt — never a pre-parsed object — so a pasted receipt gets the
// same §12.6 document-level scrutiny as a deep-linked one.
function pastedDocumentText(raw) {
  const text = raw.trim();
  if (!text) return null;
  const link = text.match(/#receipt=([A-Za-z0-9_-]+=*)/);
  if (link) return b64urlToStr(link[1]);
  if (/^[A-Za-z0-9_-]{8,}=*$/.test(text)) return b64urlToStr(text);
  return text;
}

let pasteTimer = null;
function onPasteInput() {
  // Invalidate fragment/example renders as soon as the visitor edits the box,
  // not only after the debounce. This closes the window in which an old fetch
  // could overwrite newer pasted content.
  const version = ++locationRenderVersion;
  paintReceiptState(false);
  clearTimeout(pasteTimer);
  pasteTimer = setTimeout(() => checkPasted(version), 300);
}

async function checkPasted(version = ++locationRenderVersion) {
  const isCurrent = () => version === locationRenderVersion;
  if (!isCurrent()) return;
  paintReceiptState(false);
  $("paste-error").textContent = "";
  const decoded = pastedReceiptDocumentOrError($("paste-input").value);
  if (!decoded.ok) return showReceiptError(decoded.error);
  if (LOCKED) {
    if (isCurrent()) $("paste-error").textContent = "kernel not verified — refusing to check receipts.";
    return;
  }
  const isExample = bundledExampleDocument !== null && decoded.document === bundledExampleDocument;
  paintReceiptState(isExample);
  await renderClassifiedReceiptDocument(decoded.document, { isExample, isCurrent });
}

// --- wire up -----------------------------------------------------------------
function init() {
  renderPageClaims(document);
  // Wire the receipt checker.
  if ($("paste-input")) {
    $("paste-input").addEventListener("input", onPasteInput);
    window.addEventListener("hashchange", renderLocationReceiptOrExample);
  }

  boot();
}

init();
