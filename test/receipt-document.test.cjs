// SPDX-License-Identifier: Apache-2.0
//
// ============================ TEST-ONLY — NOT SHIPPED ========================
// §12.6 document tests: the receipt on the wire and the object we validate are
// not the same thing.
//
// Every check before this one operated on the object `JSON.parse` produced,
// which is lossy about the bytes somebody signed: a repeated member collapses
// to its last occurrence, `3.0` and `3` fold together, and an escaped key name
// becomes the plain one. The exhibit (A9): a REAL host v3 receipt whose text
// carries both `"record_version": 3` and `"record_version": 2` parses to a v2
// object, classifies as v2, never runs the Object B signature check, and comes
// back `ok: true` — signature stripped, verdict forged to ALLOW, and even
// under an always-false Ed25519 oracle. The multi-family conflict rule cannot
// see it: after the parse there genuinely is one family with one value.
//
// So these tests drive the DOCUMENT entry point — validateReceipt(text) — and
// hold two lines at once:
//   1. the named collapse classes are refused, with the collapse named;
//   2. honest documents (real fixtures, both v2 dialects, values that merely
//      quote a discriminator name, nested members with those names) still
//      validate.
//
// Run:  node test/receipt-document.test.cjs
// ============================================================================
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

let failures = 0;
function check(name, got, want) {
  const pass = got === want;
  if (!pass) failures++;
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `\n      got  ${got}\n      want ${want}`}`);
}
const text = (f) => fs.readFileSync(path.join(__dirname, "fixtures", f), "utf8");

(async () => {
  const F = await import("file://" + path.resolve(__dirname, "..", "receipt-format.js"));
  const nacl = (await import("file://" + path.resolve(__dirname, "..", "vendor", "nacl.js"))).default;
  const ed = (msg, sig, pk) => nacl.sign.detached.verify(msg, sig, pk);
  const V = (doc, oracle = ed) => F.validateReceipt(doc, { ed25519Verify: oracle });
  const edFalse = () => false;
  const named = (r, fragment) => r.ok === false && r.errors.some((e) => e.includes(fragment));

  const v3text = text("host-v3-block.receipt.json");
  const v2text = text("host-v2-block.receipt.json");
  const unpText = text("unparseable-block.receipt.json");
  const fleetText = fs.readFileSync(path.resolve(__dirname, "..", "examples", "allow.receipt.json"), "utf8");
  const dup = (t) => t.replace(/"record_version"\s*:\s*3/, '"record_version": 3, "record_version": 2');

  // ---- A9: the exhibit ------------------------------------------------------
  // Real host v3 BLOCK bytes, duplicate discriminator, signature deleted,
  // verdict forged to ALLOW. Built by text surgery so the duplicate SURVIVES
  // (re-serializing a parsed object would silently drop it — which is the
  // whole point).
  const forgedObj = JSON.parse(v3text);
  delete forgedObj.signature;
  forgedObj.verdict = "ALLOW";
  forgedObj.reason = "forged allow via duplicate-key downgrade";
  forgedObj.deny_kernel = null;
  forgedObj.authorization = "approval";
  forgedObj.approval = { approval_identity: { channel: "file" },
    policy_hash: F.canonicalJsonSha256(forgedObj.kernel_config) };
  forgedObj.granted_capabilities = [{ target: "ab".repeat(32) }];
  const a9forged = dup(JSON.stringify(forgedObj, null, 2));
  const a9plain = dup(v3text);

  check("A9 wire really does carry two record_version members",
    (a9forged.match(/"record_version"/g) || []).length, 2);
  check("A9 …and JSON.parse keeps the LAST one (this is the collapse)",
    JSON.parse(a9forged).record_version, 2);
  check("A9 …with the document still saying ALLOW and carrying no Object B signature",
    /"verdict":\s*"ALLOW"/.test(a9forged) &&
      !F.scanReceiptDocument(a9forged).topLevel.has("signature"), true);

  let r = V(a9forged);
  check("A9 forged-ALLOW duplicate-key downgrade REFUSED", r.ok, false);
  check("A9 …with the duplication named",
    named(r, 'version discriminator "record_version" occurs 2 times'), true);
  check("A9 …and no version assigned (it never classifies)", r.version, null);
  check("A9 …refused with an ALWAYS-FALSE oracle too (crypto is not the gate)",
    named(V(a9forged, edFalse), "occurs 2 times"), true);
  check("A9 …refused with the signature left intact as well",
    named(V(a9plain), "occurs 2 times"), true);
  check("A9 …refused, signature intact, always-false oracle",
    named(V(a9plain, edFalse), "occurs 2 times"), true);

  // The contract, stated as a test: the OBJECT entry point cannot see any of
  // this, and says so. `document_checked: false` is the caller's warning that
  // `ok` describes an object, not a received document.
  r = F.validateReceipt(JSON.parse(a9forged), { ed25519Verify: edFalse });
  check("A9 object API still accepts the collapsed record (it never saw the bytes)", r.ok, true);
  check("A9 …and flags document_checked: false", r.document_checked, false);
  check("document path flags document_checked: true", V(v3text).document_checked, true);
  check("document path returns the parsed record for the caller",
    V(v3text).record.record_version, 3);

  // ---- the other named collapse classes -------------------------------------
  check("duplicate spelled with a \\u escape is still a duplicate",
    named(V(v3text.replace(/"record_version"\s*:\s*3/, '"record_version": 3, "record_versio\\u006e": 2')),
      "occurs 2 times"), true);
  check("lone escaped discriminator spelling refused (it verified as v3 before)",
    named(V(v3text.replace(/"record_version"/, '"record_versio\\u006e"')), "\\u escape"), true);
  check("record_version written 3.0 refused",
    named(V(v3text.replace(/"record_version"\s*:\s*3/, '"record_version": 3.0')), "written as `3.0`"), true);
  check("record_version written 3e0 refused",
    named(V(v3text.replace(/"record_version"\s*:\s*3/, '"record_version": 3e0')), "written as `3e0`"), true);
  check("record_version written 2.0 on a v2 document refused",
    named(V(v2text.replace(/"record_version"\s*:\s*2/, '"record_version": 2.0')), "written as `2.0`"), true);
  check("duplicate NON-discriminator top-level member refused",
    named(V(v2text.replace(/"reason":/, '"reason": "first", "reason":')),
      'top-level member "reason" occurs 2 times'), true);
  check("BOM-prefixed document refused, and the BOM is NOT stripped",
    named(V("﻿" + v3text), "byte-order mark"), true);
  check("trailing content after the document refused", named(V(v3text + "{}"), "trailing content"), true);
  check("non-JSON text refused as a document", named(V("not json"), "not well-formed JSON"), true);
  check("a non-string, non-object input is still refused",
    F.validateReceipt(42).ok, false);

  // ---- what a text SCANNER must not break: honest documents ------------------
  // A regex over the bytes would refuse all of these. The scanner is a
  // tokeniser, so a discriminator name inside a VALUE, or as a nested member
  // name, is not a top-level occurrence.
  check("a discriminator name quoted inside a VALUE does not refuse",
    V(v2text.replace(/"reason":\s*"[^"]*"/,
      '"reason": "policy text quotes {\\"record_version\\": 2, \\"record_version\\": 3}"')).ok, true);
  check("a NESTED member named record_version does not refuse",
    V(v2text.replace(/"kernel_identity":\s*\{/, '"kernel_identity": { "record_version": 9,')).ok, true);
  check("scanner counts only top-level members",
    F.scanReceiptDocument('{"a":{"record_version":1},"record_version":3}').topLevel.get("record_version").count, 1);

  // ---- real fixtures still validate, passed the new way ----------------------
  r = V(v3text);
  check("genuine host v3 validates through the document path",
    JSON.stringify([r.ok, r.version, r.receipt_signature_valid]), JSON.stringify([true, "v3", true]));
  r = V(v2text);
  check("genuine host v2 (record pair dialect) validates through the document path",
    JSON.stringify([r.ok, r.version, r.errors]), JSON.stringify([true, "v2", []]));
  r = V(fleetText);
  check("genuine fleet v2 (seal_receipt dialect) validates through the document path",
    JSON.stringify([r.ok, r.version, r.errors]), JSON.stringify([true, "v2", []]));
  r = V(unpText);
  check("genuine unparseable-request receipt validates through the document path", r.ok, true);
  r = V(v3text, edFalse);
  check("genuine v3 under an always-false oracle still REFUSES (document checks did not replace crypto)",
    JSON.stringify([r.ok, r.version, r.receipt_signature_valid]), JSON.stringify([false, "v3", false]));

  // ---- end to end: the shipped CLI verifier ---------------------------------
  // verify-file.cjs hands the FILE BYTES to verifyReceipt (§12.6). A file
  // carrying a duplicated discriminator must never exit 0.
  // (The library-level refusal is asserted above; the shipped verifier's own
  // seam — verifyReceipt(document) — is asserted in receipt-verify.test.cjs.)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "seal-doc-"));
  const dupFile = path.join(tmp, "dup.receipt.json");
  fs.writeFileSync(dupFile, a9forged);
  let cliOut = "", cliCode = 0;
  try {
    execFileSync(process.execPath, [path.join(__dirname, "verify-file.cjs"), dupFile],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    cliCode = e.status;
    cliOut = String(e.stdout || "") + String(e.stderr || "");
  }
  check("CLI on a duplicate-discriminator file exits 1", cliCode, 1);
  check("CLI does not report it as an authorised receipt", /AUTHORISED/.test(cliOut), false);
  fs.rmSync(tmp, { recursive: true, force: true });

  console.log(failures === 0 ? "\nDOCUMENT (§12.6) PASS" : `\n${failures} FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(1); });
