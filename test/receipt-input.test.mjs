// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { pastedReceiptDocumentOrError } from "../receipt-input.js";

test("defect 2: empty pasted input is a visible refusal, not a silent no-op", () => {
  assert.deepEqual(pastedReceiptDocumentOrError("   "), {
    ok: false,
    error: "receipt refused: empty document.",
  });
});

test("pasted helper decodes base64url receipt links and raw blobs", () => {
  assert.deepEqual(
    pastedReceiptDocumentOrError("https://example.invalid/#receipt=eyJmb28iOiJiYXIifQ"),
    { ok: true, document: "{\"foo\":\"bar\"}" },
  );
  assert.deepEqual(
    pastedReceiptDocumentOrError("eyJmb28iOiJiYXIifQ"),
    { ok: true, document: "{\"foo\":\"bar\"}" },
  );
});

test("raw JSON containing a receipt URL preserves the entire original document", () => {
  const raw = '  {"tool":"fetch","arguments":{"url":"https://example.invalid/#receipt=eyJmb28iOiJiYXIifQ"}}\n';
  assert.deepEqual(pastedReceiptDocumentOrError(raw), { ok: true, document: raw });
});

test("complete receipt with an embedded link is preserved", async () => {
  const { readFileSync } = await import("node:fs");
  const receipt = JSON.parse(readFileSync(new URL("fixtures/host-v2-block.receipt.json", import.meta.url), "utf8"));
  receipt.arguments.url = "https://example.invalid/#receipt=eyJmb28iOiJiYXIifQ";
  const raw = JSON.stringify(receipt);
  assert.deepEqual(pastedReceiptDocumentOrError(raw), { ok: true, document: raw });
  const { verifyReceipt } = await import("../receipt.js");
  assert.equal((await verifyReceipt(raw)).formatOk, false, "changed arguments still fail receipt binding");
});

test("only whole links and fragments decode; surrounding prose and trailing junk do not", () => {
  const fragment = "#receipt=eyJmb28iOiJiYXIifQ";
  assert.equal(pastedReceiptDocumentOrError(fragment).document, '{"foo":"bar"}');
  for (const raw of [`see https://example.invalid/${fragment}`, `https://example.invalid/${fragment}&extra=1`, `${fragment}!`, `{"broken":"${fragment}"`]) {
    assert.equal(pastedReceiptDocumentOrError(raw).document, raw);
  }
  assert.equal(pastedReceiptDocumentOrError("#receipt=a").ok, false);
});
