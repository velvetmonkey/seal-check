// SPDX-License-Identifier: Apache-2.0
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const fixture = JSON.parse(fs.readFileSync(
  path.join(__dirname, "fixtures", "unparseable-block.receipt.json"), "utf8"));

test("decision receipt: absent WebCrypto uses a real Ed25519 fallback", async () => {
  const { verifyConfigSignature } = await import("file://" + path.join(ROOT, "receipt.js"));
  const result = await verifyConfigSignature(fixture.signed_config, { webcrypto: null });
  assert.deepEqual(result, {
    ok: true, code: "verified", verifier: "tweetnacl",
    webcrypto: "absent", fallback: "crypto_unavailable",
  });
  assert.deepEqual(await verifyConfigSignature(fixture.signed_config,
    { webcrypto: null, naclVerify: null }), {
    ok: false, code: "crypto_unavailable", verifier: null, webcrypto: "absent",
    reason: "WebCrypto is unavailable and no Ed25519 verifier is available; open this page over https",
  });
});

test("decision receipt: a genuinely bad signature is signature_invalid", async () => {
  const { verifyConfigSignature } = await import("file://" + path.join(ROOT, "receipt.js"));
  const bad = { ...fixture.signed_config, signature:
    (fixture.signed_config.signature[0] === "0" ? "1" : "0") + fixture.signed_config.signature.slice(1) };
  const webcrypto = { subtle: {
    importKey: async () => ({}),
    verify: async () => false,
  } };
  const result = await verifyConfigSignature(bad, { webcrypto });
  assert.deepEqual(result, {
    ok: false, code: "signature_invalid", verifier: "webcrypto",
    webcrypto: "available",
  });
});

test("decision receipt: unsupported WebCrypto Ed25519 uses the same real fallback", async () => {
  const { verifyConfigSignature } = await import("file://" + path.join(ROOT, "receipt.js"));
  const webcrypto = { subtle: {
    importKey: async () => { throw new DOMException("Unrecognized algorithm", "NotSupportedError"); },
  } };
  const result = await verifyConfigSignature(fixture.signed_config, { webcrypto });
  assert.deepEqual(result, {
    ok: true, code: "verified", verifier: "tweetnacl",
    webcrypto: "ed25519_unsupported", fallback: "crypto_unavailable",
  });
  assert.deepEqual(await verifyConfigSignature(fixture.signed_config,
    { webcrypto, naclVerify: null }), {
    ok: false, code: "crypto_unavailable", verifier: null,
    webcrypto: "ed25519_unsupported",
    reason: "WebCrypto Ed25519 is unavailable: Unrecognized algorithm; open this page over https",
  });
});
