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

test("receipt link adjacent to JSON punctuation preserves the outer document", () => {
  const link = "https://example.invalid/#receipt=eyJmb28iOiJiYXIifQ";
  for (const document of [JSON.stringify({ link, verdict: "BLOCK" }), JSON.stringify([link, {}]), JSON.stringify(link)]) {
    assert.deepEqual(pastedReceiptDocumentOrError(document), { ok: true, document });
  }
});

test("only a whole receipt URL or fragment is decoded", () => {
  const fragment = "#receipt=eyJmb28iOiJiYXIifQ";
  assert.deepEqual(pastedReceiptDocumentOrError(fragment), { ok: true, document: '{"foo":"bar"}' });
  for (const document of [`prefix ${fragment}`, `https://example.invalid/${fragment}&extra=1`]) {
    assert.deepEqual(pastedReceiptDocumentOrError(document), { ok: true, document });
  }
});
