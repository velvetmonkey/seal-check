// SPDX-License-Identifier: Apache-2.0
// Headless entrypoint for the shipped browser verifier. It loads the same
// wasm, receipt.js and receipt-format.js as the UI, then verifies one file.
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const USAGE = `usage: node test/verify-file.cjs <receipt.json> [--expected-config-pubkey <64-hex>]

exit codes:
  0  AUTHORISED (signature + replay valid; supplied operator pin matches)
  1  verification, binding, replay, or signer failure
  2  usage/CLI error
  3  authentic + replay-consistent but UNPINNED
  4  REDUCED SCOPE (authorised-unparseable, §11.1): everything carried verifies
     (pinned signer, kernel-attested request binding) but the wire line is not
     re-parseable, so no independent replay is possible — NOT independently
     verified. A distinct non-passing state: never collapse it to AUTHORISED(0)
     and never to a hard failure(1).`;

const argv = process.argv.slice(2);
if (argv.length === 1 && argv[0] === "--help") {
  console.log(USAGE);
  process.exit(0);
}
let receiptPath = null, expectedConfigPubkey;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--expected-config-pubkey") {
    if (expectedConfigPubkey !== undefined || i + 1 >= argv.length) {
      console.error(USAGE); process.exit(2);
    }
    expectedConfigPubkey = argv[++i];
  } else if (argv[i].startsWith("-") || receiptPath !== null) {
    console.error(USAGE); process.exit(2);
  } else receiptPath = argv[i];
}
if (!receiptPath || (expectedConfigPubkey !== undefined && !/^[0-9a-f]{64}$/.test(expectedConfigPubkey))) {
  console.error(USAGE);
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
  const result = await R.verifyReceipt(receipt, { expectedConfigPubkey });
  console.log(`signature_valid: ${result.signature_valid}`);
  console.log(`kernel_replay_consistent: ${result.kernel_replay_consistent}`);
  console.log(`authority_trusted: ${result.authority_trusted}`);
  if (result.config_freshness) console.log(
    `config_freshness: ${result.config_freshness.field}=${result.config_freshness.value}; rollback_enforced=${result.config_freshness.rollback_enforced}`);

  if (result.outcome === "authorised") {
    console.log(`AUTHORISED: signed by pinned operator key ${receiptPath}`);
    process.exit(0);
  }
  if (result.outcome === "authorised-unparseable") {
    // §11.1 reduced scope, NOT a pass. The request binding is kernel-attested
    // (the audit's own sha256 of the judged bytes matches request_sha256) and
    // the config is Ed25519-signed by the pinned operator, but the wire line is
    // not re-parseable so no independent replay is possible. Reporting this as
    // AUTHORISED/exit-0 is the fleet P0 (parity with kit 706d644): it is a
    // distinct reduced-scope state (exit 4), never VERIFIED and never INVALID.
    console.log(`REDUCED SCOPE (authorised-unparseable): signed by pinned operator key; ` +
      `kernel-attested request binding (the kernel's audit commits to sha256 of the exact bytes it judged and it matches request_sha256); ` +
      `wire line not re-parseable (${receipt.request_parse_error}); no independent replay — NOT independently verified ${receiptPath}`);
    process.exit(4);
  }
  if (result.outcome === "unpinned") {
    console.log(`AUTHENTIC + REPLAY-CONSISTENT, authority NOT established (signed by ${receipt.signed_config.pubkey}, verify ${receipt.signed_config.pubkey} out-of-band)`);
    process.exit(3);
  }
  console.error(result.pinError === "unauthorised config signer"
    ? "FAIL unauthorised config signer"
    : `FAIL NOT VERIFIED ${receiptPath}`);
  if (result.formatErrors?.length) console.error(result.formatErrors.join("; "));
  console.error(JSON.stringify({
    formatOk: result.formatOk,
    kernelShaMatch: result.kernelShaMatch,
    requestHashMatch: result.requestHashMatch,
    bindingOk: result.bindingOk,
    bindingErrors: result.bindingErrors,
    signature_valid: result.signature_valid,
    kernel_replay_consistent: result.kernel_replay_consistent,
    authority_trusted: result.authority_trusted,
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
