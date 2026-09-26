// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { classifyReceiptFragment } from "../fragment-classifier.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const encoded = (text) => Buffer.from(text).toString("base64url");
const kind = (hash) => classifyReceiptFragment(hash).kind;

assert.equal(kind(""), "absent");
assert.equal(kind("#receipt="), "empty");
assert.equal(kind("#receipt=%20"), "whitespace-only");
assert.equal(kind("#receipt=" + encoded("   ")), "whitespace-only");
assert.equal(kind("#receipt=" + encoded(" ")), "whitespace-only");
assert.equal(kind("#not-receipt=anything"), "unparseable");
assert.equal(kind("#receipt=%%%"), "unparseable");
assert.equal(kind("#receipt=" + encoded("rubbish")), "unparseable");
assert.equal(kind("#receipt=" + encoded('{"hello":"world"}')), "wrong-shape");

const validReceipt = fs.readFileSync(path.join(ROOT, "examples", "allow.receipt.json"), "utf8");
assert.equal(kind("#receipt=" + encoded(validReceipt)), "valid-receipt");

// The encoded ceiling is inclusive, and an oversized value must be refused
// before either base64 or UTF-8 decoding begins.
const cap = 131_072;
const originalAtob = globalThis.atob;
const OriginalTextDecoder = globalThis.TextDecoder;
let atobCalls = 0;
let decoderCalls = 0;
try {
  globalThis.atob = (...args) => {
    atobCalls += 1;
    return originalAtob(...args);
  };
  globalThis.TextDecoder = class extends OriginalTextDecoder {
    constructor(...args) {
      decoderCalls += 1;
      super(...args);
    }
  };
  const oversized = classifyReceiptFragment("#receipt=" + "A".repeat(cap + 4));
  assert.equal(oversized.kind, "unparseable");
  assert.match(oversized.error, /131072 encoded characters/);
  assert.equal(atobCalls, 0);
  assert.equal(decoderCalls, 0);

  const document = validReceipt + " ".repeat(cap * 3 / 4 - Buffer.byteLength(validReceipt));
  assert.equal(encoded(document).length, cap);
  const boundary = classifyReceiptFragment("#receipt=" + encoded(document));
  assert.equal(boundary.kind, "valid-receipt");
  assert.equal(boundary.document, document);
  assert.equal(atobCalls, 1);
  assert.equal(decoderCalls, 1);
} finally {
  globalThis.atob = originalAtob;
  globalThis.TextDecoder = OriginalTextDecoder;
}

const allKinds = new Set([
  "absent", "empty", "whitespace-only", "unparseable", "wrong-shape", "valid-receipt",
]);
for (const hash of ["", "#", "#x", "#receipt", "#receipt=", "#receipt=A", "#receipt=e30", "#receipt=" + encoded(validReceipt)]) {
  assert.ok(allKinds.has(kind(hash)), `classifier left a gap for ${JSON.stringify(hash)}`);
}

console.log("fragment classifier: total six-state partition passed");

for (const [name, bytes] of [
  ["invalid continuation", [0xc3, 0x28]],
  ["overlong encoding", [0xc0, 0xaf]],
  ["lone surrogate", [0xed, 0xa0, 0x80]],
]) {
  const result = classifyReceiptFragment("#receipt=" + Buffer.from(bytes).toString("base64url"));
  assert.equal(result.kind, "unparseable", name);
  assert.equal(result.error, "receipt payload is not valid UTF-8", name);
  assert.equal(result.document, undefined, name);
}
const unicodeDocument = '{"text":"😀 Ελληνικά"}';
assert.equal(classifyReceiptFragment("#receipt=" + encoded(unicodeDocument)).document, unicodeDocument);
assert.equal(classifyReceiptFragment("#receipt=" + encoded('\ufeff' + validReceipt)).document, validReceipt);
console.log("fragment classifier: strict UTF-8, Unicode and BOM checks passed");
