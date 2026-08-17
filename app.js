// SPDX-License-Identifier: Apache-2.0
// seal-check UI wiring. No kernel logic — it calls kernel.js, renders verdicts and
// receipts, and replays the corpus. Pure client-side.
import {
  ready, verifyKernelSha, decideRaw, decideSeqRaw, buildReceipt, canonicalReceiptJson,
} from "./kernel.js";
import { CFG_STANDARD, guardTarget } from "./seal-config.js";
import { CORPUS } from "./corpus.js";
import { b64urlToStr, decodeReceiptDocument, verifyReceipt, callSummary } from "./receipt.js";
import { classifyReceiptDocument } from "./receipt-format.js";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

let SHA = null;       // {computed, pinned, match}
let LOCKED = false;   // true if kernel mismatch — refuse to emit receipts
let LAST = null;      // {decide:()=>Promise, inputBlock} for the determinism re-run

// --- examples ---------------------------------------------------------------
const EXAMPLES = {
  block: `{
  "tool": "db.execute",
  "args": { "database": "prod", "sql": "drop table users" },
  "approvals": []
}`,
  allow: `{
  "tool": "store.update",
  "args": { "op": "orset.add", "key": "k1" },
  "approvals": ["${guardTarget("store.update", { op: "orset.add", key: "k1" })}"]
}`,
};

// --- input parsing -----------------------------------------------------------
function parseApprovals(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new Error("approvals must be an array of 64-hex target strings");
  return value.map((s) => {
    if (typeof s !== "string" || !/^[0-9a-f]{64}$/.test(s)) {
      throw new Error("approval targets must be lowercase 64-hex strings, got: " + JSON.stringify(s));
    }
    return s;
  });
}

// Accept either a JSON-RPC 2.0 tools/call, or a simple {tool, args, approvals, now}.
function parseCall(text) {
  let o;
  try { o = JSON.parse(text); } catch (e) { throw new Error("not valid JSON: " + e.message); }
  if (o && o.method === "tools/call" && o.params) {
    const approvals = parseApprovals(o.approvals);
    return { tool: o.params.name, args: o.params.arguments || {}, approvals, now: 1000 };
  }
  if (o && typeof o.tool === "string") {
    const approvals = parseApprovals(o.approvals);
    return { tool: o.tool, args: o.args || {}, approvals, now: o.now ?? 1000 };
  }
  throw new Error('expected a JSON-RPC tools/call, or {"tool","args","approvals"}');
}

// (The v0 input-block builder is gone: schema v1 receipts carry the call as
// tool/arguments/now/granted_capabilities, and buildReceipt derives the
// canonical request line itself via the shared receipt-format.js.)

// --- kernel boot + self-verification ----------------------------------------
// The checker (index.html) and the audit workbench (tools.html) share this
// script; each page carries only its own elements, so tool affordances are
// wired and disabled only where they exist.
function disableToolButtons() {
  for (const id of ["run-btn", "replay-all"]) { const b = $(id); if (b) b.disabled = true; }
}

async function boot() {
  const pill = $("kernel-status");
  // file:// blocks both the wasm fetch and SubtleCrypto. Tell the user the fix up front.
  if (location.protocol === "file:") {
    LOCKED = true;
    pill.className = "pill pill-bad";
    pill.textContent = "open over http, not file:// — run  python3 -m http.server 8000  then visit http://localhost:8000";
    disableToolButtons();
    return;
  }
  try {
    SHA = await verifyKernelSha();
    $("ident-sha").textContent = SHA.computed;
    if (SHA.match) {
      pill.className = "pill pill-ok";
      pill.textContent = `kernel verified · sha256 ${SHA.computed.slice(0, 8)}…`;
      await ready();
      renderBadge();
      if ($("paste-input")) await maybeRenderDeepLinkedReceipt();
      // No receipt in the link: the paste box waits, empty. Nothing on this
      // page pretends to be a result until a receipt is actually supplied.
    } else {
      LOCKED = true;
      pill.className = "pill pill-bad";
      pill.textContent = "KERNEL MISMATCH — binary does not match the pinned sha256; receipts disabled";
      disableToolButtons();
    }
  } catch (e) {
    LOCKED = true;
    pill.className = "pill pill-bad";
    pill.textContent = "kernel could not be verified: " + e.message;
  }
}

// --- verdict + receipt rendering --------------------------------------------
function paintVerdict(node, denyNode, parsed) {
  const v = parsed.verdict === "DENY" ? "BLOCK" : parsed.verdict; // ALLOW|BLOCK|ERROR
  node.textContent = v;
  node.className = "verdict " + (v === "BLOCK" ? "v-block" : v === "ALLOW" ? "v-allow" : "v-error");
  denyNode.textContent = parsed.deny_kernel ? `denied by: ${parsed.deny_kernel}` : "";
}

// --- conformance map (receipt field -> DECISION-RECEIPT-SCHEMA v1 section) -----
// Each row: [field path, section ref(s), requirement title, value getter]. Documented
// in docs/DECISION-RECEIPT-SCHEMA.md (vendored v1 normative spec). The L0 profile's §4
// is the retired v0 Schema-K and is NOT the v1 field authority. Both block + allow
// flow through renderSpec.
const CLAUSE_MAP = [
  ["seal_receipt", "§1", "receipt schema version (v1)", (r) => r.seal_receipt],
  ["canonical_request", "§1 · §2", "canonical tools/call (parse witness)", (r) => r.canonical_request],
  ["canonical_request_sha256", "§2 · §1", "request fingerprint (sha256)", (r) => r.canonical_request_sha256.slice(0, 12) + "…"],
  ["now", "§1 · §7", "logical clock (determinism)", (r) => r.now],
  ["granted_capabilities", "§3 · §1", "presented grants (approval targets)", (r) => JSON.stringify(r.granted_capabilities)],
  ["verdict", "§5", "mediation-contract verdict", (r) => r.verdict],
  ["reason", "§1", "decision reason", (r) => r.reason],
  ["deny_kernel", "§1", "denying gate (null if allowed)", (r) => String(r.deny_kernel)],
  ["emitted_bytes", "§1 · §7", "canonical decision bytes (verbatim)", (r) => `${r.emitted_bytes.length} bytes`],
  ["certs", "§3 · §1", "per-gate seals", (r) => r.certs.map((c) => `${c.kernel}:${c.verdict}`).join(", ") || "—"],
  ["certs[].certHash", "§3", "per-gate audit seal (u64)", (r) => r.certs.map((c) => c.certHash.slice(0, 8) + "…").join(", ") || "—"],
  ["kernel_identity.wasm_sha256", "§4", "binary identity (self-verified)", (r) => r.kernel_identity.wasm_sha256.slice(0, 12) + "…"],
  ["kernel_identity.self_verified", "§4", "verified in browser", (r) => String(r.kernel_identity.self_verified)],
  ["asserted_provenance.lean_toolchain", "§4", "asserted, NOT verified here", (r) => r.asserted_provenance.lean_toolchain],
  ["asserted_provenance.axioms", "§4", "asserted axiom footprint", (r) => r.asserted_provenance.axioms.join(", ")],
  ["asserted_provenance.verified_in_browser", "§4", "MUST be false", (r) => String(r.asserted_provenance.verified_in_browser)],
];

function renderSpec(receipt) {
  const tb = $("spec-map").querySelector("tbody");
  tb.replaceChildren();
  for (const [field, ref, title, get] of CLAUSE_MAP) {
    let val;
    try { val = String(get(receipt)); } catch { val = "—"; }
    if (val.length > 84) val = val.slice(0, 84) + "…";
    const tr = el("tr");
    tr.append(el("td", "mono", field), el("td", "mono", val), el("td", "spec-ref", ref), el("td", null, title));
    tb.append(tr);
  }
  $("spec-empty").classList.add("hidden");
  $("spec-map").classList.remove("hidden");
}

function renderWitness(parsed) {
  $("cert-count").textContent = String(parsed.certs.length);
  const tb = $("witness").querySelector("tbody");
  tb.replaceChildren();
  for (const c of parsed.certs) {
    const tr = el("tr");
    tr.append(el("td", "mono", c.kernel), el("td", null, c.verdict), el("td", null, c.reason || ""), el("td", "mono", c.certHash));
    tb.append(tr);
  }
}

async function runInput() {
  $("run-error").textContent = "";
  if (LOCKED) { $("run-error").textContent = "kernel not verified — refusing to run."; return; }
  let call;
  try { call = parseCall($("call-input").value); } catch (e) { $("run-error").textContent = e.message; return; }

  let res;
  try { res = await decideRaw(CFG_STANDARD, call); }
  catch (e) { $("run-error").textContent = "kernel error: " + e.message; return; }

  const receipt = buildReceipt({ call, config: CFG_STANDARD, parsed: res.parsed, raw: res.raw, sha: SHA, signedConfig: res.signedConfig });

  paintVerdict($("verdict"), $("deny-kernel"), res.parsed);
  $("reason").textContent = res.parsed.reason;
  renderWitness(res.parsed);
  $("receipt").textContent = canonicalReceiptJson(receipt);
  renderSpec(receipt);
  $("determinism").textContent = "";
  $("result").classList.remove("hidden");

  // capture for the determinism re-run + download
  LAST = {
    json: canonicalReceiptJson(receipt),
    rerun: async () => {
      const r2 = await decideRaw(CFG_STANDARD, call);
      return canonicalReceiptJson(buildReceipt({
        call, config: CFG_STANDARD, parsed: r2.parsed, raw: r2.raw, sha: SHA, signedConfig: r2.signedConfig,
      }));
    },
  };
}

function downloadReceipt() {
  if (!LAST) return;
  const blob = new Blob([LAST.json], { type: "application/json" });
  const a = el("a");
  a.href = URL.createObjectURL(blob);
  a.download = "receipt.json";
  a.click();
  URL.revokeObjectURL(a.href);
}

async function verifyDeterminism() {
  if (!LAST) return;
  const again = await LAST.rerun();
  const same = again === LAST.json;
  const d = $("determinism");
  d.textContent = same
    ? `✓ deterministic — re-ran the same input, byte-identical receipt (${again.length} bytes).`
    : "✗ receipts differ between runs — this should never happen; the kernel may be non-deterministic.";
  d.className = "determinism " + (same ? "ok" : "bad");
}

// --- corpus replay -----------------------------------------------------------
function corpusCard(entry) {
  const card = el("div", "card");
  card.dataset.id = entry.id;
  const head = el("div", "card-head");
  head.append(el("span", "card-name", entry.name), el("span", "card-lens", entry.lens));
  card.append(head);
  card.append(el("p", "card-attack", entry.attack));
  card.append(el("p", "card-why muted", entry.why));
  const row = el("div", "row");
  const btn = el("button", "replay-btn", "Replay");
  const out = el("span", "card-result");
  btn.addEventListener("click", () => replayOne(entry, out));
  row.append(btn, out);
  card.append(row);
  return card;
}

async function replayOne(entry, out) {
  if (LOCKED) { out.textContent = "kernel not verified"; out.className = "card-result bad"; return; }
  out.textContent = "running…";
  out.className = "card-result";
  let res;
  try {
    res = entry.run === "seq"
      ? await decideSeqRaw(entry.config, entry.steps, entry.tool)
      : await decideRaw(entry.config, { tool: entry.tool, args: entry.args, approvals: entry.approvals });
  } catch (e) { out.textContent = "error: " + e.message; out.className = "card-result bad"; return null; }

  const v = res.parsed.verdict === "DENY" ? "BLOCK" : res.parsed.verdict;
  const blocked = v === "BLOCK";
  out.textContent = blocked
    ? `BLOCK ✓  (${res.parsed.deny_kernel || "?"} · seal ${(res.parsed.certHash || "").slice(0, 10)}…)`
    : `${v} ✗ expected BLOCK`;
  out.className = "card-result " + (blocked ? "ok" : "bad");
  return blocked;
}

async function replayAll() {
  let blocked = 0;
  for (const card of $("corpus").children) {
    const entry = CORPUS.find((e) => e.id === card.dataset.id);
    const out = card.querySelector(".card-result");
    const ok = await replayOne(entry, out);
    if (ok) blocked++;
  }
  $("replay-summary").textContent = `${blocked}/${CORPUS.length} blocked deterministically`;
}

// --- badge -------------------------------------------------------------------
function badgeSvg() {
  const sha = (SHA && SHA.computed ? SHA.computed : "").slice(0, 8);
  const label = "seal-checked boundary";
  const lw = 150, vw = 78, h = 20;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${lw + vw}" height="${h}" role="img" aria-label="${label}: ${sha}">
  <rect width="${lw}" height="${h}" fill="#3a3a44"/>
  <rect x="${lw}" width="${vw}" height="${h}" fill="#0a8f6e"/>
  <g fill="#fff" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="11">
    <text x="8" y="14">${label}</text>
    <text x="${lw + 8}" y="14">${sha}</text>
  </g>
</svg>`;
}

function badgeMarkdown() {
  const sha = (SHA && SHA.computed ? SHA.computed : "").slice(0, 8);
  return [
    `**seal-checked boundary** — kernel \`sha256:${sha}…\` — verified client-side, no server.`,
    `_Checks mediation of a supplied call against the verified seal kernel. Does not certify a whole server; no third-party (incl. ARIA) endorsement._`,
  ].join("\n");
}

function renderBadge() {
  const p = $("badge-preview");
  if (p) p.innerHTML = badgeSvg();
}

// Clipboard with graceful degradation. navigator.clipboard.writeText is only
// exposed in secure contexts (https / localhost); over plain http://<hostname> it is
// absent/blocked. Fall back to a hidden <textarea> + execCommand('copy'), and if even
// that fails, reveal the text pre-selected for a manual Ctrl+C. Returns a boolean.
async function copyText(text) {
  if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
    try { await navigator.clipboard.writeText(text); return true; } catch { /* fall through */ }
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, text.length);
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    if (ok) return true;
  } catch { /* fall through */ }
  return false;
}

// Last resort when both clipboard paths fail: show a visible, pre-selected textarea.
function revealForManualCopy(text) {
  let ta = $("copy-fallback");
  if (!ta) {
    ta = document.createElement("textarea");
    ta.id = "copy-fallback";
    ta.className = "copy-fallback";
    ta.setAttribute("readonly", "");
    ta.rows = 3;
    $("badge-sec").appendChild(ta);
  }
  ta.style.display = "block";
  ta.value = text;
  ta.focus();
  ta.select();
  ta.setSelectionRange(0, text.length);
}

async function copy(text, label) {
  const ok = await copyText(text);
  const fb = $("copy-fallback");
  if (ok) {
    $("copy-status").textContent = `${label} copied`;
    if (fb) fb.style.display = "none";
  } else {
    $("copy-status").textContent = `${label}: copy blocked — select the text below and copy manually`;
    revealForManualCopy(text);
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
// Receipt scenario: focus the page on the receipt, hide the interactive wedge UI.
function focusReceiptMode() {
  $("receipt-verify").classList.remove("hidden");
  for (const sec of document.querySelectorAll("main > section")) {
    if (sec.id !== "receipt-verify") sec.classList.add("hidden");
  }
  const tag = document.querySelector("header .tag");
  if (tag) tag.classList.add("hidden");
  // Compact the header: the deep-link visitor gets the answer first, not a
  // branding block. The no-backend promise is restated inside the section.
  document.body.classList.add("receipt-mode");
}
function showReceiptError(msg, focus = true) {
  if (focus) focusReceiptMode();
  $("rv-result").classList.remove("hidden");
  paintBanner("bad", "This receipt could not be read", msg);
  $("rv-table").classList.add("hidden");
  const s = $("rv-summary"); s.textContent = msg; s.className = "reason bad";
  $("rv-tech").open = true;
}

// Back to the bare page: box empty, nothing result-shaped on screen.
function hideReceiptResult() {
  $("rv-banner").className = "rv-banner hidden";
  $("rv-result").classList.add("hidden");
}

// HTML fragment describing the mediated call — demo receipts keep their
// operation-on-table phrasing, everything else falls back to tool+arguments.
function callSummaryHtml(receipt) {
  const s = callSummary(receipt);
  if (s.unparseable) {
    return `make a call whose wire line could not be re-parsed by the receipt layer ` +
      `(§11.1; raw line sha256 <code>${escapeHtml(s.rawLineShort)}</code>)`;
  }
  return s.demo
    ? `run <code>${escapeHtml(s.operation)}</code> on <code>${escapeHtml(s.table)}</code>`
    : `call <code>${escapeHtml(s.tool)}</code> with arguments <code>${escapeHtml(s.argsJson)}</code>`;
}

// The control receipt: seal was switched OFF (bypass), so there is no kernel
// decision to verify. Render it honestly, NOT as a passed verification.
function renderControlReceipt(receipt) {
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
  $("rv-context").innerHTML = `This is the <strong>control</strong> run. The gate was switched OFF, so it did not mediate the call. ` +
    `The agent asked to ${callSummaryHtml(receipt)} — with the gate absent, nothing stood in the way.`;
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
async function renderVerifiedReceipt(input, { focus = true, scroll = true } = {}) {
  if (focus) focusReceiptMode();
  $("rv-tech").open = false; // re-opened below for states that demand a close look
  let r;
  try { r = await verifyReceipt(input); } catch (e) { return showReceiptError("verification error: " + e.message, focus); }
  const receipt = r.receipt;
  if (!receipt) {
    return showReceiptError("receipt failed schema validation: " +
      (r.formatErrors || []).join("; "), focus);
  }

  if (receipt.bypass) return renderControlReceipt(receipt);
  if (r.formatOk === false) {
    return showReceiptError("receipt failed schema validation (" + (r.formatVersion || "unrecognized") + "): " +
      (r.formatErrors || []).join("; "), focus);
  }
  $("rv-result").classList.remove("hidden");
  const verdictNode = $("rv-verdict");
  verdictNode.textContent = receipt.verdict === "BLOCK" ? "REFUSED" : receipt.verdict === "ALLOW" ? "ALLOWED" : (receipt.verdict || "?");
  verdictNode.className = "verdict " + (receipt.verdict === "BLOCK" ? "v-block" : receipt.verdict === "ALLOW" ? "v-allow" : "v-error");
  $("rv-deny").textContent = receipt.deny_kernel ? `${receipt.deny_kernel} rule` : "";

  $("rv-context").innerHTML =
    `What this receipt records: an AI agent asked to ${callSummaryHtml(receipt)}, and the seal gate — ` +
    `safety software standing between the agent and the thing it wanted to touch — decided. ` +
    `The decision on record:`;

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
    $("rv-context").innerHTML += ` <em class="muted">(as the receipt claims — not confirmed by this page)</em>`;
    $("rv-tech").open = true;
  } else {
    paintBanner("bad", "This receipt does NOT check out",
      "At least one re-check failed on your device, so what this receipt says cannot be trusted. Treat it with suspicion. What does not line up:",
      plainFailures(r));
    $("rv-context").innerHTML += ` <em class="muted">(as the receipt claims — not confirmed by this page)</em>`;
    $("rv-tech").open = true;
  }

  renderCheckTable(r, receipt);
  if (scroll) $("receipt-verify").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function maybeRenderDeepLinkedReceipt() {
  let document_;
  try { document_ = decodeReceiptDocument(); } catch (e) { return showReceiptError("could not decode the receipt link: " + e.message); }
  if (!document_) return;
  // Show the received text in the box the way any pasted receipt would appear;
  // setting .value programmatically fires no input event, so this does not
  // trigger a second verification.
  $("paste-input").value = document_;
  // The raw text, not a parsed object: the link's own bytes decide both its
  // family and whether a duplicate/escaped discriminator hid that family.
  const classified = classifyReceiptDocument(document_);
  if (classified.family === "malformed")
    return showReceiptError("receipt document refused: " + classified.errors.join("; "));
  if (classified.family === "decision") return renderVerifiedReceipt(document_);
  if (classified.family === "spine") return showReceiptError(
    "This is a seal.spine/v1 proxy receipt, not the kernel decision-receipt format this page checks. " +
    "It is refused here rather than being treated as a decision receipt. Use the shipped Spine checker with the signer public key obtained out of band: " +
    "node checker/seal-receipt-check.mjs RECEIPT.json --pubkey OUT_OF_BAND_PUBKEY.",
  );
  if (classified.family === "ambiguous")
    return showReceiptError("receipt refused: it claims both a kernel decision-receipt format and the distinct seal.spine/v1 proxy format. A record must have exactly one receipt kind.");
  if (classified.family === "unknown_format")
    return showReceiptError(`receipt refused: unsupported receipt discriminator ${JSON.stringify(classified.format)}. This page verifies kernel decision receipts; seal.spine/v1 proxy receipts use the separate Spine checker.`);
  return showReceiptError("receipt refused: no recognized receipt discriminator. This page verifies kernel decision receipts; seal.spine/v1 proxy receipts use the separate Spine checker.");
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
  clearTimeout(pasteTimer);
  pasteTimer = setTimeout(checkPasted, 300);
}

async function checkPasted() {
  $("paste-error").textContent = "";
  let doc;
  try { doc = pastedDocumentText($("paste-input").value); }
  catch (e) { $("paste-error").textContent = "could not decode that as base64url: " + e.message; return; }
  if (doc === null) { hideReceiptResult(); return; }
  if (LOCKED) { $("paste-error").textContent = "kernel not verified — refusing to check receipts."; return; }
  await renderVerifiedReceipt(doc, { focus: false, scroll: false });
}

// --- wire up -----------------------------------------------------------------
function init() {
  // Checker page: the paste box. Workbench page: the tools. Wire what exists.
  if ($("paste-input")) $("paste-input").addEventListener("input", onPasteInput);

  if ($("call-input")) {
    $("call-input").value = EXAMPLES.block;
    for (const b of document.querySelectorAll(".ex")) {
      b.addEventListener("click", () => { $("call-input").value = EXAMPLES[b.dataset.ex]; });
    }
    $("run-btn").addEventListener("click", runInput);
    $("download-receipt").addEventListener("click", downloadReceipt);
    $("rerun-receipt").addEventListener("click", verifyDeterminism);
  }

  if ($("replay-all")) {
    $("replay-all").addEventListener("click", replayAll);
    const c = $("corpus");
    for (const entry of CORPUS) c.append(corpusCard(entry));
  }

  if ($("copy-badge-svg")) {
    $("copy-badge-svg").addEventListener("click", () => copy(badgeSvg(), "SVG"));
    $("copy-badge-md").addEventListener("click", () => copy(badgeMarkdown(), "Markdown"));
  }

  boot();
}

init();
