// SPDX-License-Identifier: Apache-2.0
// Headless entrypoint for the shipped browser verifier. It loads the same
// wasm, receipt.js and receipt-format.js as the UI, then verifies one file.
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const receiptPath = process.argv[2];
if (!receiptPath) {
  console.error("usage: node test/verify-file.cjs <receipt.json>");
  process.exit(2);
}

globalThis.require = require;
globalThis.__dirname = path.join(ROOT, "wasm");
(0, eval)(fs.readFileSync(path.join(ROOT, "wasm", "seal.js"), "utf8"));
globalThis.window = globalThis;
globalThis.fetch = async (p) => {
  const buf = fs.readFileSync(path.join(ROOT, p));
  return { arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) };
};

(async () => {
  const R = await import(path.join(ROOT, "receipt.js"));
  const F = await import(path.join(ROOT, "receipt-format.js"));
  const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  const roundtrip = JSON.stringify(F.assembleReceiptV2(receipt), null, 2) + "\n";
  const source = fs.readFileSync(receiptPath, "utf8");
  if (roundtrip !== source) {
    console.error(`FAIL non-canonical receipt serialization ${receiptPath}`);
    console.error(`source keys: ${Object.keys(receipt).join(",")}`);
    console.error(`roundtrip keys: ${Object.keys(F.assembleReceiptV2(receipt)).join(",")}`);
    process.exit(1);
  }
  const result = await R.verifyReceipt(receipt);
  if (result.allGood) {
    console.log(`PASS VERIFIED ${receiptPath}`);
    process.exit(0);
  }
  console.error(`FAIL NOT VERIFIED ${receiptPath}`);
  if (result.formatErrors?.length) console.error(result.formatErrors.join("; "));
  console.error(JSON.stringify({
    formatOk: result.formatOk,
    kernelShaMatch: result.kernelShaMatch,
    requestHashMatch: result.requestHashMatch,
    verdictMatch: result.verdictMatch,
    emittedBytesMatch: result.emittedBytesMatch,
    grantErrors: result.grantErrors,
    rederiveError: result.rederiveError,
  }));
  process.exit(1);
})().catch((error) => {
  console.error(`FAIL verifier error: ${error.message}`);
  process.exit(1);
});
