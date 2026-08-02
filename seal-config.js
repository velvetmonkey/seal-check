// SPDX-License-Identifier: Apache-2.0
// Shared demo config + scenario definitions for the in-browser WASM evaluator and
// the native conformance harness. Pure ES module (browser + node). NO kernel source
// here — only the public trusted-config payloads the black-box evaluator consumes.
//
// Each scenario carries the exact trusted-config + tool call that reproduces the
// verified verdict the demo narrates. Cert hashes are emitted by the kernel, not
// encoded here.
import { stableHashParts } from "./receipt-format.js";
import nacl from "./vendor/nacl.js";

// Fixed TEST-ONLY Ed25519 key from RFC 8032 test vector 1. The private seed is
// intentionally public: this key is only the deterministic trust root for the
// in-browser demo and its byte-stable fixtures, never an operator credential.
// Production receipts carry their operator's independently managed public key.
export const PUBKEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const TEST_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

const hexBytes = (hex) => Uint8Array.from(hex.match(/../g), (byte) => parseInt(byte, 16));
const bytesHex = (bytes) => [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

// TweetNaCl secret key = seed(32) || public(32). Signing is pure JS and needs no
// WebCrypto, so the in-browser demo renders in every browser and any context
// (including plain http on a LAN/tailnet IP, where crypto.subtle is undefined).
// Ed25519 is deterministic (RFC 8032), so these bytes are identical to the ones
// WebCrypto produced for the same key (verified 2026-07-14); df42 accepts them.
const _secretKey = (() => {
  const sk = new Uint8Array(64);
  sk.set(hexBytes(TEST_SEED_HEX), 0);
  sk.set(hexBytes(PUBKEY), 32);
  return sk;
})();

// SHA-256 target commitment, exact mirror of Lean Seal.stableHashParts.
export function stableHash(parts) {
  return stableHashParts(parts);
}

const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};

// Stage-A guarded target: domain + tool + complete canonical arguments and
// explicit absence frames for metadata, request state and input responses.
export function guardTarget(tool, args, server = "") {
  return stableHash([
    "seal.guard-target/v2-proposed-meta-all", ...(server === "" ? [tool] : [server, tool]), canonicalJson(args),
    "meta.absent", "", "requestState.absent", "",
    "inputResponses.absent", "",
  ]);
}

// Real Ed25519 over the EXACT compact payload string accepted by df42 seal_init.
// Return every value from the same signing operation so later receipt emission
// never needs to reconstruct (and potentially drift) the signed bytes. Kept async
// so existing callers are unchanged; the body is synchronous (nacl signs in-process).
export async function buildSignedConfig(config) {
  const payload = JSON.stringify(config);
  const signature = bytesHex(nacl.sign.detached(new TextEncoder().encode(payload), _secretKey));
  return {
    payload, signature, pubkey: PUBKEY,
    envelope: JSON.stringify({ payload, signature }),
  };
}

export async function buildEnvelope(config) {
  return (await buildSignedConfig(config)).envelope;
}

const safety = (tools) => ({ approval: { control_file: "X", ttl_seconds: 120 }, tools });
const DB = { name: "db.execute", mode: "guarded",
  match: { type: "contains_any_ci", arg: "sql", needles: ["drop", "delete", "truncate"] },
  target: [{ full_arguments: true }] };
const G = (name) => ({ name, mode: "guarded", match: { type: "always" },
  target: [{ full_arguments: true }] });
const DENY_APPROVE = { name: "approve", mode: "deny", match: { type: "always" }, target: [] };
const CONSENSUS = { roster: [1, 2, 3], votes_file: "X", high_stakes: ["payments.send"] };

// Demo 1 — determinism differential: db.execute + approve safety-gated;
// payments.send is consensus-gated (safety allows it once approved).
const CFG_DEMO1 = { epoch: 1,
  safety: safety([DB, G("payments.send"), DENY_APPROVE]),
  temporal: { policies: [] }, consensus: CONSENSUS };
// Demo 2 — policy swap: payment safety-gated; policy B adds the quorum rule.
const CFG_PAY_A = { epoch: 1, safety: safety([G("payments.send")]), temporal: { policies: [] } };
const CFG_PAY_B = { ...CFG_PAY_A, consensus: CONSENSUS };
// Demo 3 — confident hallucination: store.update safety-gated + convergence kernel.
const CFG_STORE = { epoch: 1, safety: safety([G("store.update")]),
  temporal: { policies: [] }, convergence: { tools: [{ tool: "store.update", op_arg: "op" }] } };
// Temporal — out-of-order / stale-capability: a destructive db.execute AFTER a session.revoke is
// forbidden by a real temporal policy. Needs an ordered trace (revoke then the call), so it is
// decided as a sequence (seal_init once, a seal_decide per step) — see decideSeq.
export const CFG_TEMPORAL = { epoch: 1,
  safety: safety([DB, G("session.revoke")]),
  temporal: { policies: [{ name: "no-destructive-after-revoke", type: "no_after",
    trigger: ["session.revoke"], forbidden: ["db.execute"] }] } };
// "Fire your own" box: a rich multi-kernel config covering the common tools.
export const CFG_STANDARD = { epoch: 1,
  safety: safety([DB, G("payments.send"), G("session.revoke"),
                  G("store.update"), G("key.use"), DENY_APPROVE]),
  temporal: { policies: [] }, consensus: CONSENSUS,
  convergence: { tools: [{ tool: "store.update", op_arg: "op" }] } };

// scenario key -> {config, tool, args, approvals, demo, label}
export const SCENARIOS = {
  "destructive-sql": { config: CFG_DEMO1, tool: "db.execute", args: { database: "prod", sql: "drop table users" }, approvals: [], demo: 1, label: "Drop the production users table (no approval)" },
  "self-approve":    { config: CFG_DEMO1, tool: "approve", args: { target: 1 }, approvals: [], demo: 1, label: "Self-approve my own destructive call" },
  "wire-40k":        { config: CFG_DEMO1, tool: "payments.send", args: { amount: 40000, to: "GB-unlisted" }, approvals: [guardTarget("payments.send", { amount: 40000, to: "GB-unlisted" })], demo: 1, label: "Wire £40,000 to an unlisted account" },
  "pay-before":      { config: CFG_PAY_A, tool: "payments.send", args: { amount: 40000, to: "supplier-77" }, approvals: [guardTarget("payments.send", { amount: 40000, to: "supplier-77" })], demo: 2, label: "Policy A — no quorum rule" },
  "pay-after":       { config: CFG_PAY_B, tool: "payments.send", args: { amount: 40000, to: "supplier-77" }, approvals: [guardTarget("payments.send", { amount: 40000, to: "supplier-77" })], demo: 2, label: "Policy B — + 2-of-3 quorum" },
  "store-safe":      { config: CFG_STORE, tool: "store.update", args: { op: "orset.add", key: "k1" }, approvals: [guardTarget("store.update", { op: "orset.add", key: "k1" })], demo: 3, label: "store.update { op: orset.add }" },
  "store-subtle":    { config: CFG_STORE, tool: "store.update", args: { op: "assign", key: "k1" }, approvals: [guardTarget("store.update", { op: "assign", key: "k1" })], demo: 3, label: "store.update { op: assign }" },
};

const rpc = (tool, args, id = 1) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: tool, arguments: args } });

// Build the seal_decide step-input JSON for a scenario (or a custom tool call).
// `votes` is the raw consensus votes-file text (NDJSON lines
// `{"acceptor":<nat>,"value":"<tool>"}`); default "" is byte-identical to before, so
// existing scenarios/conformance are unaffected.
export function buildStepInput({ tool, args, approvals = [], now = 1000, votes = "", id = 1 }) {
  return JSON.stringify({ line: rpc(tool, args, id), now,
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
