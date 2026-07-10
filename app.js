// SPDX-License-Identifier: Apache-2.0
// seal-check UI wiring. No kernel logic — it calls kernel.js, renders verdicts and
// receipts, and replays the corpus. Pure client-side.
import {
  ready, verifyKernelSha, decideRaw, decideSeqRaw, buildReceipt, canonicalReceiptJson,
} from "./kernel.js";
import { CFG_STANDARD, stableHash } from "./seal-config.js";
import { CORPUS } from "./corpus.js";
import { decodeReceiptParam, verifyReceipt, callSummary } from "./receipt.js";

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
  "approvals": ["${stableHash(["store.update", "store"])}"]
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
async function boot() {
  const pill = $("kernel-status");
  // file:// blocks both the wasm fetch and SubtleCrypto. Tell the user the fix up front.
  if (location.protocol === "file:") {
    LOCKED = true;
    pill.className = "pill pill-bad";
    pill.textContent = "open over http, not file:// — run  python3 -m http.server 8000  then visit http://localhost:8000";
    $("run-btn").disabled = true;
    $("replay-all").disabled = true;
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
      await maybeRenderDeepLinkedReceipt();
    } else {
      LOCKED = true;
      pill.className = "pill pill-bad";
      pill.textContent = "KERNEL MISMATCH — binary does not match the pinned sha256; receipts disabled";
      $("run-btn").disabled = true;
      $("replay-all").disabled = true;
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

  const receipt = buildReceipt({ call, config: CFG_STANDARD, parsed: res.parsed, raw: res.raw, sha: SHA });

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
        call, config: CFG_STANDARD, parsed: r2.parsed, raw: r2.raw, sha: SHA,
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
  $("badge-preview").innerHTML = badgeSvg();
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
// Receipt scenario: focus the page on the receipt, hide the interactive wedge UI.
function focusReceiptMode() {
  $("receipt-verify").classList.remove("hidden");
  for (const sec of document.querySelectorAll("main > section")) {
    if (sec.id !== "receipt-verify") sec.classList.add("hidden");
  }
  const tag = document.querySelector("header .tag");
  if (tag) tag.classList.add("hidden");
}
function showReceiptError(msg, focus = true) {
  if (focus) focusReceiptMode(); else $("receipt-verify").classList.remove("hidden");
  const s = $("rv-summary"); s.textContent = msg; s.className = "reason bad";
}

// HTML fragment describing the mediated call — demo receipts keep their
// operation-on-table phrasing, everything else falls back to tool+arguments.
function callSummaryHtml(receipt) {
  const s = callSummary(receipt);
  return s.demo
    ? `run <code>${escapeHtml(s.operation)}</code> on <code>${escapeHtml(s.table)}</code>`
    : `call <code>${escapeHtml(s.tool)}</code> with arguments <code>${escapeHtml(s.argsJson)}</code>`;
}

// The control receipt: seal was switched OFF (bypass), so there is no kernel
// decision to verify. Render it honestly, NOT as a passed verification.
function renderControlReceipt(receipt) {
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
async function renderVerifiedReceipt(receipt, { focus = true, note = "" } = {}) {
  if (focus) focusReceiptMode(); else $("receipt-verify").classList.remove("hidden");
  let r;
  try { r = await verifyReceipt(receipt); } catch (e) { return showReceiptError("verification error: " + e.message, focus); }

  if (receipt.bypass) return renderControlReceipt(receipt);
  if (r.formatOk === false) {
    return showReceiptError("receipt failed schema validation (" + (r.formatVersion || "unrecognized") + "): " +
      (r.formatErrors || []).join("; "), focus);
  }
  const verdictNode = $("rv-verdict");
  verdictNode.textContent = receipt.verdict === "BLOCK" ? "REFUSED" : receipt.verdict === "ALLOW" ? "ALLOWED" : (receipt.verdict || "?");
  verdictNode.className = "verdict " + (receipt.verdict === "BLOCK" ? "v-block" : receipt.verdict === "ALLOW" ? "v-allow" : "v-error");
  $("rv-deny").textContent = receipt.deny_kernel ? `${receipt.deny_kernel} rule` : "";

  $("rv-context").innerHTML = (note ? `<strong>${escapeHtml(note)}</strong> ` : "") +
    `An AI agent's tool-call was mediated by the seal gate: it asked to ${callSummaryHtml(receipt)}. ` +
    `The gate's decision, re-checked below:`;

  const ul = $("rv-checks"); ul.textContent = "";
  ul.append(rvLine(r.kernelShaMatch, `kernel binary self-verified (sha256 ${r.kernelSha.slice(0, 12)}…, matches the receipt)`));
  ul.append(rvLine(r.requestHashMatch, `request bytes match the receipt's fingerprint (${(receipt.canonical_request_sha256 || "").slice(0, 12)}…)`));
  if (r.verdictMatch === null) {
    ul.append(rvLine(null, receipt.bypass ? "verdict not re-derivable: this receipt had the gate switched OFF (the control)" : "verdict not re-derivable (receipt carries no policy)"));
  } else {
    ul.append(rvLine(r.verdictMatch, `verdict reproduced on-device: ${r.rederived === "BLOCK" ? "REFUSED" : r.rederived} (re-ran the exact request through the kernel)`));
  }
  if (r.emittedBytesMatch !== null && r.emittedBytesMatch !== undefined) {
    ul.append(rvLine(r.emittedBytesMatch, "emitted decision bytes byte-identical to the re-run"));
  }
  // Neutral disclosure, not a warning: opaque commitments are how this
  // fire-your-own-target box works, so the boundary is named, calmly.
  if (r.hasOpaqueGrants) {
    ul.append(rvLine(null, `${r.opaqueGrants} capability grant(s) carried as opaque target commitments — expected for this fire-your-own-target box. seal-check verifies the decision, not what the grants bind to.`));
  }

  $("rv-json").textContent = JSON.stringify(receipt, null, 2);
  const s = $("rv-summary");
  s.textContent = r.allGood
    ? "All decision checks passed. The verified kernel really did produce this decision from these committed inputs, and you just reproduced it."
    : "One or more checks did not pass. Treat this receipt with suspicion.";
  s.className = "reason " + (r.allGood ? "ok" : "bad");
  $("receipt-verify").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function maybeRenderDeepLinkedReceipt() {
  let receipt;
  try { receipt = decodeReceiptParam(); } catch (e) { return showReceiptError("could not decode the receipt link: " + e.message); }
  if (!receipt) return;
  await renderVerifiedReceipt(receipt);
}

// Demo the deep-link flow without a link: build a real receipt through the
// kernel, optionally tamper with it, and push it through the same verifier UI.
async function demoReceipt(tamper) {
  const status = $("demo-receipt-status");
  if (LOCKED) { status.textContent = "kernel not verified — demo disabled."; return; }
  status.textContent = "";
  try {
    const call = parseCall(EXAMPLES.allow);
    const res = await decideRaw(CFG_STANDARD, call);
    const receipt = buildReceipt({ call, config: CFG_STANDARD, parsed: res.parsed, raw: res.raw, sha: SHA });
    if (tamper) receipt.verdict = receipt.verdict === "ALLOW" ? "BLOCK" : "ALLOW";
    await renderVerifiedReceipt(receipt, {
      focus: false,
      note: tamper
        ? "Demo: this receipt was deliberately tampered with (verdict flipped) — verification must fail."
        : "Demo: a genuine receipt, built by this page's kernel a moment ago.",
    });
  } catch (e) {
    status.textContent = "demo error: " + e.message;
  }
}

// --- wire up -----------------------------------------------------------------
function init() {
  $("call-input").value = EXAMPLES.block;
  for (const b of document.querySelectorAll(".ex")) {
    b.addEventListener("click", () => { $("call-input").value = EXAMPLES[b.dataset.ex]; });
  }
  $("run-btn").addEventListener("click", runInput);
  $("demo-receipt-good").addEventListener("click", () => demoReceipt(false));
  $("demo-receipt-tampered").addEventListener("click", () => demoReceipt(true));
  $("download-receipt").addEventListener("click", downloadReceipt);
  $("rerun-receipt").addEventListener("click", verifyDeterminism);
  $("replay-all").addEventListener("click", replayAll);
  $("copy-badge-svg").addEventListener("click", () => copy(badgeSvg(), "SVG"));
  $("copy-badge-md").addEventListener("click", () => copy(badgeMarkdown(), "Markdown"));

  const c = $("corpus");
  for (const entry of CORPUS) c.append(corpusCard(entry));

  boot();
}

init();
