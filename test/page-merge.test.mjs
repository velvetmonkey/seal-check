// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const ROOT = resolve(import.meta.dirname, "..");

function readPage(file) {
  return readFileSync(resolve(ROOT, file), "utf8");
}

test("audit workbench controls are present on index.html", () => {
  const html = readPage("index.html");
  assert.match(html, /<section id="workbench">/);
  for (const id of ["call-input", "run-btn", "replay-all", "badge-sec", "spec-map"]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.match(html, /id="call-receipt-summary"/);
  assert.equal([...html.matchAll(/id="receipt-summary"/g)].length, 1);
});

test("tools.html redirects to index.html while preserving fragments", () => {
  const html = readPage("tools.html");
  assert.match(html, /location\.replace\("index\.html" \+ location\.hash\)/);
  for (const anchor of ["#check", "#replay", "#badge-sec", "#spec"]) {
    assert.match(html, new RegExp(`index\\.html${anchor}`));
  }
});
