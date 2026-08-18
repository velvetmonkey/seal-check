// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { LEGACY_TOOLS_ANCHOR_TARGETS, legacyToolsDestination } from "../legacy-tools-redirect.js";

const ROOT = resolve(import.meta.dirname, "..");
const readPage = (file) => readFileSync(resolve(ROOT, file), "utf8");
const oldIds = [
  "kernel-status", "more-tools", "check", "call-input", "run-btn", "run-error", "result", "verdict",
  "deny-kernel", "reason", "witness-wrap", "cert-count", "witness", "download-receipt", "rerun-receipt",
  "determinism", "receipt-summary-heading", "receipt-summary", "receipt", "replay", "replay-all",
  "replay-summary", "corpus", "badge-sec", "badge-preview", "copy-badge-svg", "copy-badge-md", "copy-status",
  "spec", "spec-empty", "spec-map", "claims", "ident-sha",
];

test("merged workbench remains on index.html", () => {
  const html = readPage("index.html");
  assert.match(html, /<section id="workbench">/);
  for (const id of ["call-input", "run-btn", "replay-all", "badge-sec", "spec-map"]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.match(html, /id="call-receipt-summary"/);
});

test("every old tools.html id has a deliberate destination", () => {
  assert.deepEqual(new Set(oldIds), new Set(Object.keys(LEGACY_TOOLS_ANCHOR_TARGETS)));
  const html = readPage("index.html");
  for (const target of Object.values(LEGACY_TOOLS_ANCHOR_TARGETS))
    assert.match(html, new RegExp(`id="${target}"`));
});

test("redirect preserves every query shape byte-for-byte", () => {
  for (const query of ["?a=b", "?flag", "?empty=", "?a=1&a=2", "?na%6de=%E2%98%83", "?"]) {
    const out = new URL(legacyToolsDestination(`https://example.test/tools.html${query}#check`));
    assert.equal(out.pathname, "/index.html");
    assert.equal(out.search, query === "?" ? "" : query);
    assert.equal(out.hash, "#check");
  }
});

test("more-tools lands on workbench and receipt-summary refuses the near-miss", () => {
  assert.equal(new URL(legacyToolsDestination("https://example.test/tools.html#more-tools")).hash, "#workbench");
  assert.equal(new URL(legacyToolsDestination("https://example.test/tools.html#receipt-summary")).hash, "#legacy-receipt-summary");
  assert.match(readPage("index.html"), /Legacy anchor refused/);
});
