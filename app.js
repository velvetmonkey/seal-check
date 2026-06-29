// SPDX-License-Identifier: Apache-2.0
// seal-check UI wiring. No kernel logic — it calls kernel.js, renders verdicts and
// receipts, and replays the corpus. Pure client-side.
import {
  ready, verifyKernelSha, decideRaw, decideSeqRaw, buildReceipt, canonicalReceiptJson,
} from "./kernel.js";
import { CFG_STANDARD, stableHash } from "./seal-config.js";
import { CORPUS } from "./corpus.js";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

let SHA = null;       // {computed, pinned, match}
let LOCKED = false;   // true if kernel mismatch — refuse to emit receipts
let LAST = null;      // {decide:()=>Promise, inputBlock} for the determinism re-run

// --- examples (raw strings: approval targets are u64 and must not pass through
// JSON.stringify, which would mangle them past Number.MAX_SAFE_INTEGER) ---------
const EXAMPLES = {
  block: `{
  "tool": "db.execute",
  "args": { "database": "prod", "sql": "drop table users" },
  "approvals": []
}`,
  allow: `{
  "tool": "store.update",
  "args": { "op": "orset.add", "key": "k1" },
  "approvals": [${stableHash(["store.update", "store"]).toString()}]
}`,
};

// --- input parsing -----------------------------------------------------------
// Approval targets are u64 hashes that exceed Number.MAX_SAFE_INTEGER, so JSON.parse
// would silently round them. Read them straight from the raw text as BigInt instead.
function parseApprovalsRaw(text) {
  const m = text.match(/"approvals"\s*:\s*\[([\s\S]*?)\]/);
  if (!m) return null;
  const inner = m[1].trim();
  if (!inner) return [];
  return inner.split(",").map((s) => s.trim()).filter(Boolean).map((s) => {
    if (!/^\d+$/.test(s)) throw new Error("approval targets must be integer hashes, got: " + s);
    return BigInt(s);
  });
}

// Accept either a JSON-RPC 2.0 tools/call, or a simple {tool, args, approvals, now}.
function parseCall(text) {
  let o;
  try { o = JSON.parse(text); } catch (e) { throw new Error("not valid JSON: " + e.message); }
  const approvals = parseApprovalsRaw(text) || [];
  if (o && o.method === "tools/call" && o.params) {
    return { tool: o.params.name, args: o.params.arguments || {}, approvals, now: 1000 };
  }
  if (o && typeof o.tool === "string") {
    return { tool: o.tool, args: o.args || {}, approvals, now: o.now ?? 1000 };
  }
  throw new Error('expected a JSON-RPC tools/call, or {"tool","args","approvals"}');
}

// Build the receipt input block. request_line/now come from the kernel step;
// approvals come from the parsed call as decimal strings so the u64 targets stay
// exact in the receipt (JSON.parse of the step would round them).
function inputBlockFrom(stepStr, call) {
  const s = JSON.parse(stepStr);
  return { request_line: s.line, now: s.now, approvals: call.approvals.map(String) };
}

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

  const inputBlock = inputBlockFrom(res.step, call);
  const receipt = buildReceipt({ input: inputBlock, parsed: res.parsed, raw: res.raw, sha: SHA });

  paintVerdict($("verdict"), $("deny-kernel"), res.parsed);
  $("reason").textContent = res.parsed.reason;
  renderWitness(res.parsed);
  $("receipt").textContent = canonicalReceiptJson(receipt);
  $("determinism").textContent = "";
  $("result").classList.remove("hidden");

  // capture for the determinism re-run + download
  LAST = {
    json: canonicalReceiptJson(receipt),
    rerun: async () => {
      const r2 = await decideRaw(CFG_STANDARD, call);
      return canonicalReceiptJson(buildReceipt({
        input: inputBlockFrom(r2.step, call), parsed: r2.parsed, raw: r2.raw, sha: SHA,
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

// --- wire up -----------------------------------------------------------------
function init() {
  $("call-input").value = EXAMPLES.block;
  for (const b of document.querySelectorAll(".ex")) {
    b.addEventListener("click", () => { $("call-input").value = EXAMPLES[b.dataset.ex]; });
  }
  $("run-btn").addEventListener("click", runInput);
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
