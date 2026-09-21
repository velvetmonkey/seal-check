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

// Both URL and paste consumers must refuse bytes before JSON can hide damage.
test("shared receipt decoder refuses invalid UTF-8 through every public decode path", async () => {
  const { b64urlToStr, decodeReceiptDocument, decodeReceiptParam } = await import("../receipt.js");
  const { classifyReceiptFragment } = await import("../fragment-classifier.js");
  const previousLocation = globalThis.location;
  try {
    for (const bytes of [[0xc3, 0x28], [0xc0, 0xaf], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xe2, 0x82]]) {
      const encoded = Buffer.concat([Buffer.from('{"value":"'), Buffer.from(bytes), Buffer.from('"}')]).toString("base64url");
      assert.throws(() => b64urlToStr(encoded), /not valid UTF-8/);
      const fragment = "#receipt=" + encoded;
      globalThis.location = { hash: fragment };
      assert.throws(() => decodeReceiptDocument(), /not valid UTF-8/);
      assert.throws(() => decodeReceiptParam(), /not valid UTF-8/);
      const classified = classifyReceiptFragment(fragment);
      assert.equal(classified.kind, "unparseable");
      assert.match(classified.error, /could not decode.*not valid UTF-8/);
      assert.equal(classified.document, undefined);
      for (const input of [encoded, fragment, "https://example.invalid/" + fragment]) {
        const result = pastedReceiptDocumentOrError(input);
        assert.equal(result.ok, false);
        assert.match(result.error, /could not decode.*not valid UTF-8/);
      }
    }
  } finally {
    if (previousLocation === undefined) delete globalThis.location;
    else globalThis.location = previousLocation;
  }
});

test("shared decoder bounds decoded bytes before atob, including padded inputs", async () => {
  const { b64urlToStr, MAX_RECEIPT_DECODED_BYTES } = await import("../receipt.js");
  const { classifyReceiptFragment } = await import("../fragment-classifier.js");
  assert.equal(MAX_RECEIPT_DECODED_BYTES, 1048576);
  for (const size of [MAX_RECEIPT_DECODED_BYTES - 2, MAX_RECEIPT_DECODED_BYTES - 1, MAX_RECEIPT_DECODED_BYTES]) {
    const bytes = Buffer.alloc(size, 97);
    for (const encoding of ["base64url", "base64"]) {
      assert.equal(b64urlToStr(bytes.toString(encoding)), bytes.toString());
    }
  }
  const atob = globalThis.atob;
  let called = false;
  globalThis.atob = () => { called = true; throw new Error("atob must not run"); };
  try {
    for (const size of [MAX_RECEIPT_DECODED_BYTES + 1, MAX_RECEIPT_DECODED_BYTES + 2, MAX_RECEIPT_DECODED_BYTES + 3]) {
      for (const encoding of ["base64url", "base64"]) {
        const encoded = Buffer.alloc(size, 97).toString(encoding);
        assert.throws(() => b64urlToStr(encoded), /exceeds 1048576 decoded bytes/);
        const fragment = "#receipt=" + encoded;
        const classified = classifyReceiptFragment(fragment);
        assert.equal(classified.kind, "unparseable");
        assert.match(classified.error, /exceeds 1048576 decoded bytes/);
        for (const input of [encoded, fragment]) {
          const result = pastedReceiptDocumentOrError(input);
          assert.equal(result.ok, false);
          assert.match(result.error, /exceeds 1048576 decoded bytes/);
        }
      }
    }
    assert.equal(called, false);
  } finally { globalThis.atob = atob; }
  const unicode = "é".repeat(MAX_RECEIPT_DECODED_BYTES / 2);
  assert.equal(b64urlToStr(Buffer.from(unicode).toString("base64url")), unicode);
  assert.throws(() => b64urlToStr(Buffer.from(unicode + "é").toString("base64url")), /exceeds/);
  for (const invalid of ["A", "!!!", "YQ===", "Y Q", "Y+Q", "Y/Q"]) {
    assert.throws(() => b64urlToStr(invalid));
  }
  assert.equal(b64urlToStr(""), "");
  assert.equal(b64urlToStr(Buffer.from("literal � stays valid UTF-8").toString("base64url")), "literal � stays valid UTF-8");
});

test("all shipped JSON fixtures roundtrip within the shared decoder ceiling", async () => {
  const { readdirSync, readFileSync } = await import("node:fs");
  const { b64urlToStr, MAX_RECEIPT_DECODED_BYTES } = await import("../receipt.js");
  for (const directory of [new URL("../examples/", import.meta.url), new URL("fixtures/", import.meta.url)]) {
    for (const file of readdirSync(directory).filter(name => name.endsWith(".json"))) {
      const bytes = readFileSync(new URL(file, directory));
      assert.ok(bytes.length <= MAX_RECEIPT_DECODED_BYTES, file);
      assert.equal(b64urlToStr(bytes.toString("base64url")), bytes.toString("utf8"), file);
    }
  }
});
