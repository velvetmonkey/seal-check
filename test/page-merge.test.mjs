// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import {
  LEGACY_TOOLS_ANCHOR_TARGETS,
  legacyToolsDestination,
  legacyToolsRequestedHash,
  rememberLegacyToolsNavigation,
  revealMissingLegacyToolsFragment,
} from "../legacy-tools-redirect.js";

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

function redirectControl(sourceHref) {
  const destination = legacyToolsDestination(sourceHref);
  const source = new URL(sourceHref);
  const location = new URL(destination);
  const stored = new Map();
  const storage = {
    getItem: (key) => stored.get(key) ?? null,
    removeItem: (key) => stored.delete(key),
    setItem: (key, value) => stored.set(key, value),
  };
  rememberLegacyToolsNavigation(storage, destination, legacyToolsRequestedHash(source));

  const notice = { hidden: true };
  const namedMessage = { hidden: false };
  const collapsedMessage = { hidden: true };
  const fragmentName = { textContent: "" };
  const ids = new Set([...readPage("index.html").matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]));
  const document = {
    referrer: "",
    getElementById(id) {
      if (id === "legacy-missing-fragment") return notice;
      if (id === "legacy-missing-fragment-named") return namedMessage;
      if (id === "legacy-missing-fragment-collapsed") return collapsedMessage;
      if (id === "legacy-missing-fragment-name") return fragmentName;
      return ids.has(id) ? { id } : null;
    },
  };
  const result = revealMissingLegacyToolsFragment({ document, location, storage });
  return { collapsedMessage, destination: location, fragmentName, namedMessage, notice, result };
}

test("control 1: known old more-tools id lands on its section with no notice", () => {
  assert.match(readPage("tools.html"), /rememberLegacyToolsNavigation\(sessionStorage/);
  const control = redirectControl("https://example.test/tools.html#more-tools");
  assert.equal(control.destination.hash, "#workbench");
  assert.equal(control.result, "found");
  assert.equal(control.notice.hidden, true);
});

test("control 2: unknown old id shows a visible notice naming the requested fragment", () => {
  assert.match(readPage("index.html"), /revealMissingLegacyToolsFragment\(\{ document, location, storage: sessionStorage \}\)/);
  const control = redirectControl("https://example.test/tools.html#never-existed");
  assert.equal(control.result, "missing", "unresolved legacy fragment must not fail silently");
  assert.equal(control.notice.hidden, false);
  assert.equal(control.fragmentName.textContent, "never-existed");
  assert.match(readPage("index.html"), /This page moved[\s\S]*requested section[\s\S]*no longer exists/);
});

test("fragment matching is case-sensitive", () => {
  const control = redirectControl("https://example.test/tools.html#MORE-TOOLS");
  assert.equal(control.result, "missing", "case-mismatched legacy fragment must not be reported as found");
  assert.equal(control.notice.hidden, false);
  assert.equal(control.fragmentName.textContent, "MORE-TOOLS");
});

test("percent-encoded spelling is not normalized into a legacy id", () => {
  const control = redirectControl("https://example.test/tools.html#more%2Dtools");
  assert.equal(control.result, "missing", "encoded legacy fragment must be checked exactly as requested");
  assert.equal(control.notice.hidden, false);
  assert.equal(control.fragmentName.textContent, "more%2Dtools");
});

test("control 3: tools redirect with no hash has no fragment and shows no notice", () => {
  const control = redirectControl("https://example.test/tools.html");
  assert.equal(control.destination.hash, "");
  assert.equal(control.result, "no-fragment");
  assert.equal(control.notice.hidden, true);
});

test("control 4: every reported collapsing input shows the generic notice", () => {
  for (const [name, fragment] of [
    ["space", " "],
    ["tab", "\t"],
    ["line feed", "\n"],
    ["carriage return", "\r"],
    ["null", "\0"],
  ]) {
    const control = redirectControl(`https://example.test/tools.html#${fragment}`);
    assert.equal(control.result, "missing", `${name} fragment must not fail silently`);
    assert.equal(control.notice.hidden, false, `${name} fragment must show the notice`);
    assert.equal(control.namedMessage.hidden, true, `${name} fragment must not render a raw value`);
    assert.equal(control.collapsedMessage.hidden, false, `${name} fragment must use generic wording`);
    assert.equal(control.fragmentName.textContent, "", `${name} fragment must not reach page text`);
  }
});

test("control 5: invented form-feed collapsing input shows the generic notice", () => {
  const control = redirectControl("https://example.test/tools.html#\f");
  assert.equal(control.result, "missing", "form-feed fragment must not fail silently");
  assert.equal(control.notice.hidden, false);
  assert.equal(control.namedMessage.hidden, true);
  assert.equal(control.collapsedMessage.hidden, false);
  assert.equal(control.fragmentName.textContent, "");
});

test("control 6: a bare hash counts as a request and shows the generic notice", () => {
  const control = redirectControl("https://example.test/tools.html#");
  assert.equal(control.result, "missing", "bare hash must not fail silently");
  assert.equal(control.notice.hidden, false);
  assert.equal(control.namedMessage.hidden, true);
  assert.equal(control.collapsedMessage.hidden, false);
  assert.equal(control.fragmentName.textContent, "");
});
