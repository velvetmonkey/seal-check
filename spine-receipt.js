// SPDX-License-Identifier: Apache-2.0
// Browser port of seal/checker/seal-receipt-check.mjs.  Its canonicalisation
// is a byte-for-byte COPY of the sealer's canonical function, not a second
// independent implementation: a bug here can agree with the sealer's bug.
import nacl from "./vendor/nacl.js";
import { sha256Hex } from "./receipt-format.js";

const DOMAIN = "seal.receipt-seal/v1\n";
const encoder = new TextEncoder();
const hex = (value) => /^[0-9a-f]+$/.test(value) && value.length % 2 === 0
  ? Uint8Array.from(value.match(/../g), (pair) => parseInt(pair, 16)) : null;

// Kept byte-identical in behaviour to spine/receipt-seal.cjs and the offline
// checker.  Do not describe this as an independent canonicalisation.
export function canonical(value) {
  if (value === null || typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const names = Object.keys(value).sort((a, b) => {
    const left = encoder.encode(a), right = encoder.encode(b);
    for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
      if (left[i] !== right[i]) return left[i] - right[i];
    }
    return left.length - right.length;
  });
  return `{${names.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function refuse(code, reason) { return { accepted: false, code, reason }; }

async function verifySignature(message, signature, publicKey, { webcrypto = globalThis.crypto, naclVerify = nacl.sign.detached.verify } = {}) {
  if (webcrypto && webcrypto.subtle) {
    try {
      const key = await webcrypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
      return { ok: await webcrypto.subtle.verify("Ed25519", key, signature, message) };
    } catch (error) {
      // A browser may expose SubtleCrypto but lack Ed25519.  TweetNaCl is the
      // shipped detached-verification fallback, including on plain HTTP.
      if (typeof naclVerify === "function") return { ok: naclVerify(message, signature, publicKey) };
      return { error };
    }
  }
  if (typeof naclVerify === "function") return { ok: naclVerify(message, signature, publicKey) };
  return { unavailable: true };
}

// Same checks, order, and refusal codes as checker/seal-receipt-check.mjs.
// The caller supplies the public key out of band; never read one from receipt.
export async function checkSpineReceipt(receipt, pubKeyHex, cryptoOptions) {
  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt))
    return refuse("not_a_receipt", "input is not a JSON object");
  if (receipt.receipt !== "seal.spine/v1")
    return refuse("unknown_format", `unknown receipt format: ${receipt.receipt}`);
  const seal = receipt.seal;
  if (!seal || typeof seal !== "object" || Array.isArray(seal))
    return refuse("unsealed", "receipt carries no seal; it cannot be checked");
  if (seal.alg !== "ed25519") return refuse("unknown_algorithm", `unknown seal algorithm: ${seal.alg}`);
  for (const field of ["decision", "tool", "arguments"]) {
    if (!(field in receipt)) return refuse("incomplete_receipt", `receipt has no ${field} field to check`);
  }
  if (sha256Hex(encoder.encode(String(receipt.decision))) !== seal.decision_sha256)
    return refuse("decision_binding_mismatch", "the recorded decision does not match its sealed commitment");
  if (sha256Hex(encoder.encode(String(receipt.tool))) !== seal.tool_sha256)
    return refuse("tool_binding_mismatch", "the recorded tool does not match its sealed commitment");
  if (sha256Hex(encoder.encode(canonical(receipt.arguments))) !== seal.args_sha256)
    return refuse("arguments_binding_mismatch", "the recorded arguments do not match their sealed commitment");
  if (sha256Hex(encoder.encode(canonical({ args: receipt.arguments, tool: receipt.tool }))) !== seal.effect_sha256)
    return refuse("effect_binding_mismatch", "the recorded effect does not match its sealed commitment");
  if (typeof seal.sig !== "string" || !/^[0-9a-f]{128}$/.test(seal.sig))
    return refuse("signature_malformed", "the seal signature is missing or malformed");
  if (typeof pubKeyHex !== "string" || !/^[0-9a-f]{64}$/.test(pubKeyHex))
    return refuse("pubkey_invalid", "the supplied public key is unusable: public key must be 32-byte hex");
  const { sig, ...sealWithoutSig } = seal;
  const checked = await verifySignature(
    encoder.encode(DOMAIN + canonical({ ...receipt, seal: sealWithoutSig })), hex(sig), hex(pubKeyHex), cryptoOptions,
  );
  if (checked.unavailable)
    return refuse("crypto_unavailable", "WebCrypto is unavailable and no Ed25519 verifier is available; open this page over https");
  if (checked.error)
    return refuse("crypto_unavailable", `WebCrypto Ed25519 is unavailable: ${checked.error.message}; open this page over https`);
  if (!checked.ok)
    return refuse("signature_invalid", "the seal signature does not verify against the supplied public key");
  return { accepted: true, code: "accept", decision: receipt.decision, tool: receipt.tool,
    checks: ["decision", "tool", "arguments", "effect", "signature"] };
}
