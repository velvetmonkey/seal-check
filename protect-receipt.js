// SPDX-License-Identifier: Apache-2.0
// Browser port of seal/checker/seal-receipt-v2.mjs at 858d2cd.
// Preserves its document, shape, commitments, signature and replay checks.
// The shared v2 discriminator is disambiguated before this strict checker;
// no host decision-receipt validation is relaxed. No producer identity claim.
import nacl from "./vendor/nacl.js";
import { sha256Hex } from "./receipt-format.js";
import { replayProtectRaw } from "./kernel.js";

const ORDER = ["seal_receipt", "tool", "action", "arguments", "now", "kernel_config", "granted_capabilities", "kernel_inputs", "verdict", "reason", "replay", "signature"];
const SIGNATURE_KEYS_SORTED = ["algorithm", "value"];
const HEX64 = /^[0-9a-f]{64}$/;
const encoder = new TextEncoder();
const hex = (text) => Uint8Array.from(text.match(/../g), (pair) => parseInt(pair, 16));
const fail = (message, code = "invalid_receipt") => { const e = new Error(message); e.code = code; throw e; };

// This is an independent implementation of the written specification:
// ECMAScript own-property enumeration order, never producer sorting.
export function canonical(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value) || !Number.isSafeInteger(value)) fail("number is not a finite safe integer", "number_not_canonical");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  fail("unsupported JSON value", "value_not_canonical");
}

export function sha256(text) { return sha256Hex(encoder.encode(text)); }

// JSON.parse keeps the last duplicate member. Walk the bytes first so that a
// verifier never signs or judges an ambiguous interpretation.
// Unlike the CLI scanner, consume member-leading whitespace as valid JSON;
// signatures still cover canonical parsed values and duplicates still refuse.
function scanDocument(text) {
  let i = 0;
  const ws = () => { while (/[\t\n\r ]/.test(text[i] || "")) i++; };
  const string = () => { const start = i; if (text[i++] !== '"') fail("expected string", "read_failed"); while (i < text.length) { const c = text[i++]; if (c === "\\") { if (i >= text.length) fail("truncated escape", "read_failed"); if (text[i++] === "u") { if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i, i + 4))) fail("bad unicode escape", "read_failed"); i += 4; } } else if (c === '"') return JSON.parse(text.slice(start, i)); else if (c.charCodeAt(0) < 32) fail("control character in string", "read_failed"); } fail("truncated string", "read_failed"); };
  const value = () => { ws(); const c = text[i]; if (c === '"') { string(); return; } if (c === "{") { object(); return; } if (c === "[") { array(); return; } if (text.startsWith("true", i)) { i += 4; return; } if (text.startsWith("false", i)) { i += 5; return; } if (text.startsWith("null", i)) { i += 4; return; } const n = text.slice(i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/); if (!n) fail("bad value", "read_failed"); i += n[0].length; };
  const array = () => { i++; ws(); if (text[i] === "]") { i++; return; } for (;;) { value(); ws(); if (text[i] === ",") { i++; continue; } if (text[i] === "]") { i++; return; } fail("truncated array", "read_failed"); } };
  const object = () => { i++; ws(); const names = new Set(); if (text[i] === "}") { i++; return; } for (;;) { ws(); const name = string(); if (names.has(name)) fail(`duplicate member ${name}`, "duplicate_member"); names.add(name); ws(); if (text[i++] !== ":") fail("expected colon", "read_failed"); value(); ws(); if (text[i] === ",") { i++; continue; } if (text[i] === "}") { i++; return; } fail("truncated object", "read_failed"); } };
  ws(); value(); ws(); if (i !== text.length) fail("trailing or truncated JSON", "read_failed");
}

export function read(input) {
  let text;
  if (typeof input === "string") text = input;
  else if (input instanceof Uint8Array) {
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(input); }
    catch (e) { fail(`ill-formed UTF-8: ${e.message}`, "read_failed"); }
  } else fail("receipt must be UTF-8 bytes or a string", "read_failed");
  scanDocument(text);
  try { return JSON.parse(text); } catch (e) { fail(`JSON parse failed: ${e.message}`, "read_failed"); }
}

function validate(r) {
  if (!r || typeof r !== "object" || Array.isArray(r)) fail("envelope is not an object");
  if (r.seal_receipt !== "v2") fail("unsupported receipt schema");
  let orderIndex = -1;
  for (const k of Object.keys(r)) { const next = ORDER.indexOf(k); if (next <= orderIndex) fail("member order is not the v2 order", "member_order"); orderIndex = next; }
  if (typeof r.tool !== "string" || !r.tool || (!r.arguments || typeof r.arguments !== "object" || Array.isArray(r.arguments))) fail("tool and arguments are required");
  if (!Number.isSafeInteger(r.now) || r.now < 0) fail("now must be a non-negative safe integer");
  if (!r.kernel_config || typeof r.kernel_config !== "object" || Array.isArray(r.kernel_config)) fail("kernel_config is required");
  if (!Array.isArray(r.granted_capabilities) || !r.kernel_inputs || typeof r.kernel_inputs !== "object" || Array.isArray(r.kernel_inputs)) fail("kernel inputs are required");
  if (!Array.isArray(r.kernel_inputs.approvals) || !r.kernel_inputs.approvals.every((x) => typeof x === "string")) fail("approvals must be strings");
  for (const k of ["votes", "grants", "forecasts"]) if (typeof r.kernel_inputs[k] !== "string") fail(`kernel_inputs.${k} must be a string`);
  if (r.kernel_inputs.approval_handle_sha256 !== undefined && !HEX64.test(r.kernel_inputs.approval_handle_sha256))
    fail("kernel_inputs.approval_handle_sha256 must be 64 lowercase hex");
  const targets = r.granted_capabilities.map((g) => g && g.target);
  if (!r.granted_capabilities.every((g) => g && typeof g === "object" && typeof g.target === "string") ||
      JSON.stringify(targets) !== JSON.stringify(r.kernel_inputs.approvals))
    fail("granted capabilities do not match approvals", "input_mismatch");
  if (!["ALLOW", "BLOCK", "ERROR"].includes(r.verdict) || typeof r.reason !== "string") fail("verdict and reason are required");
  if (!r.replay || !HEX64.test(r.replay.args_sha256) || !HEX64.test(r.replay.config_sha256)) fail("replay commitments are required");
  if (r.replay.args_sha256 !== sha256(canonical(r.arguments))) fail("arguments commitment mismatch", "commitment_mismatch");
  if (r.replay.config_sha256 !== sha256(canonical(r.kernel_config))) fail("kernel config commitment mismatch", "commitment_mismatch");
}

export async function replay(r) {
  if (r.kernel_inputs.grants !== "" || r.kernel_inputs.forecasts !== "")
    fail("grants and forecasts are inert in the current kernel and must be empty", "inert_input");
  const x = await replayProtectRaw(r.kernel_config, {
    tool: r.tool, args: r.arguments, approvals: r.kernel_inputs.approvals, now: r.now,
    votes: r.kernel_inputs.votes, grants: r.kernel_inputs.grants, forecasts: r.kernel_inputs.forecasts,
    granted_capabilities: r.granted_capabilities,
  });
  if (x.verdict !== r.verdict) fail(`recorded verdict ${r.verdict} does not reproduce as ${x.verdict}`, "verdict_mismatch");
  return x;
}

function checkSignature(r, keyHex) {
  if (!r.signature) return false;
  const signatureKeys = Object.keys(r.signature).sort();
  const unexpectedKeys = signatureKeys.filter((key) => !SIGNATURE_KEYS_SORTED.includes(key));
  if (unexpectedKeys.length === 1) fail(`signature.${unexpectedKeys[0]}: unexpected member`, "unexpected_member");
  if (unexpectedKeys.length > 1)
    fail(`signature: exactly the members algorithm,value required; unexpected members: ${unexpectedKeys.join(",")}`, "unexpected_member");
  if (JSON.stringify(signatureKeys) !== JSON.stringify(SIGNATURE_KEYS_SORTED))
    fail("signature: exactly the members algorithm,value required", "signature_mismatch");
  if (r.signature.algorithm !== "ed25519" || typeof r.signature.value !== "string" || !/^[0-9a-f]{128}$/.test(r.signature.value)) fail("signature is malformed", "signature_mismatch");
  if (!/^[0-9a-f]{64}$/.test(keyHex || "")) return false;
  const unsigned = { ...r }; delete unsigned.signature;
  if (!nacl.sign.detached.verify(encoder.encode(canonical(unsigned)), hex(r.signature.value), hex(keyHex)))
    fail("signature mismatch", "signature_mismatch");
  return true;
}

export async function verify(text, { publicKeyHex, authorityRoot, occurrenceWitness } = {}) {
  const r = read(text); validate(r);
  // Phase A has no authority-chain or occurrence-witness format to validate.
  // Refuse those inputs explicitly: their presence is not evidence. Until the
  // formats and checks exist, positive VERIFY is deliberately unreachable.
  if (authorityRoot !== undefined) fail("authority roots cannot be checked by the v2 verifier");
  if (occurrenceWitness !== undefined) fail("occurrence witnesses cannot be checked by the v2 verifier");
  const signed = checkSignature(r, publicKeyHex);
  const replayed = await replay(r);
  if (r.action === "ALLOW" && replayed.verdict !== "ALLOW")
    fail("signed action ALLOW requires replayed verdict ALLOW", "action_verdict_mismatch");
  return {
    read: true,
    validate: true,
    replay: true,
    signature: signed,
    authority: signed ? "UNPINNED / CALLER-SUPPLIED" : "NOT ESTABLISHED",
    occurrence: "NOT ESTABLISHED",
    verify: false,
    receipt: r,
  };
}

export function format(result) { return `Document structure       ${result.read ? "VALID" : "INVALID"}\nSignature and bindings   ${result.signature ? "VALID" : "UNVERIFIED"}\nVerifier-local verdict   ${result.replay ? "REPRODUCED" : "NOT REPRODUCED"}\nAuthority key            ${result.authority}\nEvent occurrence         ${result.occurrence}\n                         ------------------\nREAD      ${result.read ? "available" : "unavailable"}\nVALIDATE  ${result.validate ? "available" : "unavailable"}\nREPLAY    ${result.replay ? "available" : "unavailable"}\nVERIFY    ${result.verify ? "VERIFIED" : "UNVERIFIED"}`; }

