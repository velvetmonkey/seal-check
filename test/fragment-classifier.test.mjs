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

const allKinds = new Set([
  "absent", "empty", "whitespace-only", "unparseable", "wrong-shape", "valid-receipt",
]);
for (const hash of ["", "#", "#x", "#receipt", "#receipt=", "#receipt=A", "#receipt=e30", "#receipt=" + encoded(validReceipt)]) {
  assert.ok(allKinds.has(kind(hash)), `classifier left a gap for ${JSON.stringify(hash)}`);
}

console.log("fragment classifier: total six-state partition passed");
