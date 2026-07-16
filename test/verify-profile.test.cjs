// SPDX-License-Identifier: Apache-2.0
// Profile self-check (seal-assurance-kit docs/VERIFY-PROFILES.md): this
// repo's verifier copy declares VERIFY_PROFILE = "P-ENFORCE", and its CLI
// gate behaves per the P-ENFORCE row of the spec table on local fixtures:
//   pass + pin            -> exit 0  VERIFIED
//   pass, no pin          -> exit 3  UNPINNED   (ceiling without a trust anchor)
//   config-less parseable -> exit 1  FAIL       (signed_config binding required)
//   legit §11.1 + pin     -> exit 4  REDUCED    (distinct, never success)
// This is the CI-enforceable half of the profile teeth; the fleet
// differentials (manual, in seal-assurance-kit) check cross-repo agreement.
//
// A red leg here means this copy is OFF ITS DECLARED PROFILE — a finding to
// report, not a test to re-green by editing the declaration.
"use strict";
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const PIN = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
// Spec grammar (VERIFY-PROFILES.md §6) — extract without importing.
const DECL_RE = /VERIFY_PROFILE[^"']*["'](P-[A-Z]+)["']/;

let failures = 0;
function check(name, cond, detail = "") {
  if (!cond) failures++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond || !detail ? "" : `   (${detail})`}`);
}

const cli = (...args) => spawnSync(process.execPath,
  [path.join(ROOT, "test", "verify-file.cjs"), ...args], { encoding: "utf8" });

(async () => {
  // --- declaration ---
  const src = fs.readFileSync(path.join(ROOT, "receipt.js"), "utf8");
  const m = src.match(DECL_RE);
  check("declaration: receipt.js declares VERIFY_PROFILE per the spec grammar", !!m,
    "no regex-extractable VERIFY_PROFILE in receipt.js");
  check("declaration: profile is P-ENFORCE", m && m[1] === "P-ENFORCE", m && m[1]);
  const R = await import(path.join(ROOT, "receipt.js"));
  check("declaration: the exported constant agrees with the extractable text",
    R.VERIFY_PROFILE === "P-ENFORCE", String(R.VERIFY_PROFILE));

  // --- behaviour: the P-ENFORCE row on local fixtures ---
  const passFile = path.join(ROOT, "examples", "allow.receipt.json");
  const reducedFile = path.join(ROOT, "test", "fixtures", "unparseable-block.receipt.json");

  let r = cli(passFile, "--expected-config-pubkey", PIN);
  check("P-ENFORCE: pass + pin -> exit 0 VERIFIED", r.status === 0, `exit ${r.status}`);

  r = cli(passFile);
  check("P-ENFORCE: pass, no pin -> exit 3 UNPINNED (never a bare pass)",
    r.status === 3, `exit ${r.status}`);

  // config-less parseable: delete signed_config -> format-layer hard fail.
  const receipt = JSON.parse(fs.readFileSync(passFile, "utf8"));
  delete receipt.signed_config;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seal-check-profile-"));
  const configless = path.join(dir, "configless.receipt.json");
  fs.writeFileSync(configless, JSON.stringify(receipt, null, 2) + "\n");
  r = cli(configless, "--expected-config-pubkey", PIN);
  check("P-ENFORCE: config-less parseable -> exit 1 FAIL (binding required)",
    r.status === 1, `exit ${r.status}`);
  fs.rmSync(dir, { recursive: true, force: true });

  r = cli(reducedFile, "--expected-config-pubkey", PIN);
  check("P-ENFORCE: legit §11.1 + pin -> exit 4 REDUCED (distinct, not success, not invalid)",
    r.status === 4, `exit ${r.status}`);
  check("P-ENFORCE: the reduced banner is not the success banner",
    !(`${r.stdout}${r.stderr}`).includes("AUTHORISED: signed by pinned operator key"));

  console.log(failures === 0
    ? "\nVERIFY-PROFILE SELF-CHECK PASS — this copy is on its declared P-ENFORCE profile"
    : `\n${failures} FAILURE(S) — this copy is off its declared profile; report as a finding`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
