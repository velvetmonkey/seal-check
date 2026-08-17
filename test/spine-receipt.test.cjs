// SPDX-License-Identifier: Apache-2.0
// Fixtures came from actual `seal demo` and protected-path proxy runs; no demo
// is started here, so CI tests the emitted artifacts themselves.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const fixture = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, "examples", name), "utf8"));
const key = fs.readFileSync(path.join(ROOT, "examples", "spine-signer.pub"), "utf8").trim();

(async () => {
  const { checkSpineReceipt } = await import("file://" + path.join(ROOT, "spine-receipt.js"));
  const { receiptFamily, classifyReceiptDocument } = await import("file://" + path.join(ROOT, "receipt-format.js"));

  test("genuine signed demo receipt ACCEPTS all five checks", async () => {
    const result = await checkSpineReceipt(fixture("spine-allow.receipt.json"), key);
    assert.deepEqual(result, { accepted: true, code: "accept", decision: "ALLOW", tool: "demo.mutate",
      checks: ["decision", "tool", "arguments", "effect", "signature"] });
  });

  for (const [name, expected] of [
    ["spine-arguments-tampered.receipt.json", "arguments_binding_mismatch"],
    ["spine-different-payload.receipt.json", "signature_invalid"],
    ["spine-unsigned-protect.receipt.json", "unsealed"],
    ["spine-not-a-receipt.json", "unknown_format"],
  ]) test(`${name} refuses ${expected}`, async () => {
    const result = await checkSpineReceipt(fixture(name), key);
    assert.equal(result.code, expected);
  });

  test("every other reference refusal is named", async () => {
    const good = fixture("spine-allow.receipt.json");
    const cases = [
      [null, key, "not_a_receipt"],
      [{ receipt: "seal.spine/v2" }, key, "unknown_format"],
      [{ receipt: "seal.spine/v1" }, key, "unsealed"],
      [{ receipt: "seal.spine/v1", seal: { alg: "rsa" } }, key, "unknown_algorithm"],
      [{ receipt: "seal.spine/v1", seal: { alg: "ed25519" }, decision: "ALLOW", tool: "t" }, key, "incomplete_receipt"],
      [{ ...good, decision: "BLOCK" }, key, "decision_binding_mismatch"],
      [{ ...good, tool: "other" }, key, "tool_binding_mismatch"],
      [{ ...good, seal: { ...good.seal, args_sha256: "0".repeat(64) } }, key, "arguments_binding_mismatch"],
      [{ ...good, seal: { ...good.seal, effect_sha256: "0".repeat(64) } }, key, "effect_binding_mismatch"],
      [{ ...good, seal: { ...good.seal, sig: "x" } }, key, "signature_malformed"],
      [good, "no", "pubkey_invalid"],
    ];
    for (const [receipt, pubkey, code] of cases) assert.equal((await checkSpineReceipt(receipt, pubkey)).code, code);
  });

  test("missing cryptography refuses by name and names https", async () => {
    const result = await checkSpineReceipt(fixture("spine-allow.receipt.json"), key,
      { webcrypto: null, naclVerify: null });
    assert.equal(result.code, "crypto_unavailable");
    assert.match(result.reason, /https/);
  });

  test("discriminator routes exactly two families and refuses ambiguity", () => {
    assert.deepEqual(receiptFamily(fixture("spine-allow.receipt.json")), { family: "spine" });
    assert.deepEqual(receiptFamily({ seal_receipt: "v1" }), { family: "decision" });
    assert.deepEqual(receiptFamily({ receipt: "seal.spine/v2" }), { family: "unknown_format", format: "seal.spine/v2" });
    assert.deepEqual(receiptFamily({ receipt: "seal.spine/v1", seal_receipt: "v1" }), { family: "ambiguous" });
    assert.deepEqual(receiptFamily({ hello: "world" }), { family: "not_a_receipt" });
  });

  test("document intake fails closed with distinct honest refusals", () => {
    const empty = classifyReceiptDocument("");
    const truncated = classifyReceiptDocument('{"receipt":"seal.spine/v1"');
    const wrongShape = classifyReceiptDocument('{"receipt":"seal.spine/v1","hello":true}');
    assert.equal(empty.family, "malformed");
    assert.match(empty.errors.join("; "), /empty document/);
    assert.equal(truncated.family, "malformed");
    assert.match(truncated.errors.join("; "), /not well-formed JSON/);
    assert.equal(wrongShape.family, "spine");
    return checkSpineReceipt(wrongShape.record, key).then((result) => {
      assert.equal(result.code, "unsealed");
    });
  });
})().catch((error) => { console.error(error); process.exitCode = 1; });
