// SPDX-License-Identifier: Apache-2.0
// Shared demo config + scenario definitions for the in-browser WASM evaluator and
// the native conformance harness. Pure ES module (browser + node). NO kernel source
// here — only the public trusted-config payloads the black-box evaluator consumes.
//
// Each scenario carries the exact trusted-config + tool call that reproduces the
// verified verdict the demo narrates. Cert hashes are emitted by the kernel, not
// encoded here.

export const PUBKEY = "demo-pk";

// FNV-style hash, exact mirror of Seal.Hash.stableHashParts (for approval targets).
export function stableHash(parts) {
  let acc = 14695981039346656037n;
  const M = 1099511628211n, MOD = 1n << 64n;
  for (const ch of parts.join("|")) acc = (acc * M + BigInt(ch.codePointAt(0))) % MOD;
  return acc;
}

// u64 targets exceed Number.MAX_SAFE_INTEGER -> serialize BigInt as exact JSON
// integer literals (sentinel + strip quotes) so Lean's getNat reads them precisely.
function stringifyBig(obj) {
  return JSON.stringify(obj, (_k, v) => (typeof v === "bigint" ? `__BIG__${v}__BIG__` : v))
    .replace(/"__BIG__(\d+)__BIG__"/g, "$1");
}

export function buildEnvelope(payload, pubkey = PUBKEY) {
  const compact = JSON.stringify(payload);
  return JSON.stringify({ payload: compact, signature: `stub-ed25519:${pubkey}:${compact}` });
}

const safety = (tools) => ({ approval: { control_file: "X", ttl_seconds: 120 }, tools });
const DB = { name: "db.execute", mode: "guarded",
  match: { type: "contains_any_ci", arg: "sql", needles: ["drop", "delete", "truncate"] },
  target: [{ literal: "db" }, { arg: "database" }, { literal: "write" }, { arg: "sql" }] };
const G = (name, t) => ({ name, mode: "guarded", match: { type: "always" }, target: t });
const DENY_APPROVE = { name: "approve", mode: "deny", match: { type: "always" }, target: [] };
const CONSENSUS = { roster: [1, 2, 3], votes_file: "X", high_stakes: ["payments.send"] };

// Demo 1 — determinism differential: db.execute + approve safety-gated;
// payments.send is consensus-gated (safety allows it once approved).
const CFG_DEMO1 = { epoch: 1,
  safety: safety([DB, G("payments.send", [{ literal: "pay" }]), DENY_APPROVE]),
  temporal: { policies: [] }, consensus: CONSENSUS };
// Demo 2 — policy swap: payment safety-gated; policy B adds the quorum rule.
const CFG_PAY_A = { epoch: 1, safety: safety([G("payments.send", [{ literal: "pay" }])]), temporal: { policies: [] } };
const CFG_PAY_B = { ...CFG_PAY_A, consensus: CONSENSUS };
// Demo 3 — confident hallucination: store.update safety-gated + convergence kernel.
const CFG_STORE = { epoch: 1, safety: safety([G("store.update", [{ literal: "store" }])]),
  temporal: { policies: [] }, convergence: { tools: [{ tool: "store.update", op_arg: "op" }] } };
// Temporal — out-of-order / stale-capability: a destructive db.execute AFTER a session.revoke is
// forbidden by a real temporal policy. Needs an ordered trace (revoke then the call), so it is
// decided as a sequence (seal_init once, a seal_decide per step) — see decideSeq.
export const CFG_TEMPORAL = { epoch: 1,
  safety: safety([DB, G("session.revoke", [{ literal: "revoke" }])]),
  temporal: { policies: [{ name: "no-destructive-after-revoke", type: "no_after",
    trigger: ["session.revoke"], forbidden: ["db.execute"] }] } };
// "Fire your own" box: a rich multi-kernel config covering the common tools.
export const CFG_STANDARD = { epoch: 1,
  safety: safety([DB, G("payments.send", [{ literal: "pay" }]), G("session.revoke", [{ literal: "revoke" }]),
                  G("store.update", [{ literal: "store" }]), G("key.use", [{ literal: "key" }]), DENY_APPROVE]),
  temporal: { policies: [] }, consensus: CONSENSUS,
  convergence: { tools: [{ tool: "store.update", op_arg: "op" }] } };

const PAY_T = stableHash(["payments.send", "pay"]);
const STORE_T = stableHash(["store.update", "store"]);

// scenario key -> {config, tool, args, approvals, demo, label}
export const SCENARIOS = {
  "destructive-sql": { config: CFG_DEMO1, tool: "db.execute", args: { database: "prod", sql: "drop table users" }, approvals: [], demo: 1, label: "Drop the production users table (no approval)" },
  "self-approve":    { config: CFG_DEMO1, tool: "approve", args: { target: 1 }, approvals: [], demo: 1, label: "Self-approve my own destructive call" },
  "wire-40k":        { config: CFG_DEMO1, tool: "payments.send", args: { amount: 40000, to: "GB-unlisted" }, approvals: [PAY_T], demo: 1, label: "Wire £40,000 to an unlisted account" },
  "pay-before":      { config: CFG_PAY_A, tool: "payments.send", args: { amount: 40000, to: "supplier-77" }, approvals: [PAY_T], demo: 2, label: "Policy A — no quorum rule" },
  "pay-after":       { config: CFG_PAY_B, tool: "payments.send", args: { amount: 40000, to: "supplier-77" }, approvals: [PAY_T], demo: 2, label: "Policy B — + 2-of-3 quorum" },
  "store-safe":      { config: CFG_STORE, tool: "store.update", args: { op: "orset.add", key: "k1" }, approvals: [STORE_T], demo: 3, label: "store.update { op: orset.add }" },
  "store-subtle":    { config: CFG_STORE, tool: "store.update", args: { op: "assign", key: "k1" }, approvals: [STORE_T], demo: 3, label: "store.update { op: assign }" },
};

const rpc = (tool, args, id = 1) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: tool, arguments: args } });

// Build the seal_decide step-input JSON for a scenario (or a custom tool call).
// `votes` is the raw consensus votes-file text (NDJSON lines
// `{"acceptor":<nat>,"value":"<tool>"}`); default "" is byte-identical to before, so
// existing scenarios/conformance are unaffected.
export function buildStepInput({ tool, args, approvals = [], now = 1000, votes = "", id = 1 }) {
  return stringifyBig({ line: rpc(tool, args, id), now,
    approvals: approvals.map((t) => ({ target: t })), votes, grants: "", forecasts: "" });
}

// Parse seal_decide output -> demo-friendly verdict.
export function parseVerdict(raw, tool) {
  const v = JSON.parse(raw);
  if (v.error) return { verdict: "ERROR", reason: v.error, certs: [], tool };
  if (v.route === "passthrough") return { verdict: "ALLOW", reason: "not a mediated tool call (passthrough)", certs: [], tool };
  const audit = v.audit ? JSON.parse(v.audit) : { certs: [], verdict: v.route === "block" ? "deny" : "allow" };
  const certs = (audit.certs || []).map((c) => ({ kernel: c.kernel, verdict: c.verdict, reason: c.reason, certHash: String(c.certHash) }));
  const denied = certs.find((c) => c.verdict === "deny");
  return {
    verdict: v.route === "block" ? "DENY" : "ALLOW",
    reason: denied ? `${denied.kernel} kernel: ${denied.reason}` : "every gating kernel allows",
    deny_kernel: denied ? denied.kernel : null,
    certs, tool,
    // single representative cert for the determinism lane (the deny cert, else first)
    certHash: (denied || certs[0] || {}).certHash || null,
  };
}
