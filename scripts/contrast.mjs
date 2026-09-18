#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// WCAG 2.1 contrast audit for the seal-check palette.
//
// Contrast is a number, not an opinion. This reads the custom properties out of
// style.css (so it cannot drift from the stylesheet) and computes the contrast
// ratio for every foreground/background pair the pages actually render. The
// pair list below is a declared inventory: each entry names where on the page
// that combination appears, so a reviewer can check the inventory against the
// CSS rather than take a screenshot's word for it.
//
// The page now ships two themes (light/dark), switched via a `data-theme`
// attribute on <html> — the same mechanism and token names as the seal docs
// site (velvetmonkey/seal, docs/src/styles/custom.css). Each theme is its own
// `:root[data-theme='...']` block; this script extracts and audits both,
// independently, against the same declared PAIRS inventory.
//
// Thresholds (WCAG 2.1):
//   body   >= 4.5:1  (1.4.3, normal-size text)
//   large  >= 3.0:1  (1.4.3, >=18.66px bold or >=24px regular)
//   ui     >= 3.0:1  (1.4.11, borders and other non-text UI boundaries)
//
// Exit 0 when every pair passes in every theme, 1 when any pair fails, 2 on a
// missing token. Node only, no dependencies. Run: node scripts/contrast.mjs

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CSS = readFileSync(resolve(ROOT, "style.css"), "utf8");

// --- token extraction -------------------------------------------------------

function extractBlock(selector) {
  const start = CSS.indexOf(selector);
  if (start === -1) throw new Error(`selector not found in style.css: ${selector}`);
  const braceOpen = CSS.indexOf("{", start);
  const braceClose = CSS.indexOf("}", braceOpen);
  const block = CSS.slice(braceOpen, braceClose);
  const tokens = Object.create(null);
  for (const m of block.matchAll(/--seal-([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8})\s*;/g)) {
    tokens[m[1]] = m[2];
  }
  return tokens;
}

const THEMES = [
  { name: "light", tokens: extractBlock(":root[data-theme='light']") },
  { name: "dark", tokens: extractBlock(":root[data-theme='dark']") },
];

// --- colour maths -----------------------------------------------------------

function parseHex(hex) {
  let h = hex.replace("#", "");
  if (h.length === 3) h = h.split("").map((c) => c + c).join("");
  if (h.length === 8) h = h.slice(0, 6); // opaque-over-white is not assumed; see NOTE
  if (h.length !== 6) throw new Error(`unsupported colour: ${hex}`);
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
}

// WCAG 2.1 relative luminance.
function luminance(hex) {
  const [r, g, b] = parseHex(hex).map((c) =>
    c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4),
  );
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function ratio(fg, bg) {
  const a = luminance(fg), b = luminance(bg);
  const [hi, lo] = a > b ? [a, b] : [b, a];
  return (hi + 0.05) / (lo + 0.05);
}

// --- the declared inventory -------------------------------------------------
// [foreground, background, threshold class, where it renders]
// A name resolves to the --seal-name custom property; a literal "#rrggbb" is
// a colour hardcoded outside the palette.

const PAIRS = [
  // body copy
  ["text", "bg", "body", "body copy, h1/h2/h3, .rv-subline, .rv-limit p, table cells"],
  ["text", "surface", "body", ".claim p, textarea, details bodies"],
  ["text", "accent-soft", "body", "<code> inside body copy"],
  ["muted", "bg", "body", ".muted, details summary, .ident dd, .rv-table .rvt-detail"],
  ["muted", "accent-soft", "body", "<code> inside .muted paragraphs"],
  ["muted", "danger-soft", "body", ".rv-table tr.rvt-row-fail td.rvt-detail"],
  ["accent", "bg", "body", "links, .rvt-detail-toggle"],

  // verdict + state text (mono, 13px+, so held to the body threshold, not large)
  ["success", "bg", "body", ".v-allow, .rvt-pass, .rv-ok"],
  ["success", "surface", "body", ".claim.proves h3"],
  ["success", "success-soft", "body", ".pill-ok, .lab-ok, .rv-banner.ok .rv-headline"],
  ["danger", "bg", "body", ".v-block, .rvt-fail, .rv-fails li, .rv-bad, .error"],
  ["danger", "danger-soft", "body", ".pill-bad, .rv-banner.bad text, .rvt-row-fail state cell, .legacy-fragment-notice"],
  ["warning", "bg", "body", ".v-error, .rvt-skip"],
  ["warning", "surface", "body", ".claim.notproves h3 on a panel"],
  ["warning", "warning-soft", "body", ".lab-asserted, .rv-banner.warn .rv-headline"],
  ["text", "success-soft", "body", ".rv-banner.ok .rv-subline"],
  ["text", "danger-soft", "body", ".rv-banner.bad .rv-subline, .rvt-row-fail td"],
  ["text", "warning-soft", "body", ".rv-banner.warn .rv-subline"],

  // non-text UI boundaries. --seal-border (the ported family divider colour)
  // is intentionally NOT audited here: it is a decorative content-divider
  // (section rules, table row rules), not a 1.4.11 "user interface
  // component" a visitor must perceive to operate the page. Components whose
  // boundary a visitor must actually see (form field, toggle, disclosure)
  // use --seal-muted instead, which this does audit.
  ["muted", "bg", "ui", "textarea, .pill, disclosure and theme-toggle borders"],
  ["accent", "bg", "ui", "textarea focus ring, disclosure hover border"],
  ["success", "bg", "ui", ".pill-ok, .claim.proves, .rv-banner.ok, .lab-ok borders"],
  ["success", "success-soft", "ui", "the same borders against their own fill"],
  ["danger", "bg", "ui", ".pill-bad, .rv-banner.bad borders"],
  ["danger", "danger-soft", "ui", "the same borders and .legacy-fragment-notice against their own fill"],
  ["warning", "bg", "ui", ".claim.notproves, .rv-banner.warn, .lab-asserted borders"],
  ["warning", "warning-soft", "ui", "the same borders against their own fill"],

  // large text (>=24px): the re-check headline
  ["success", "success-soft", "large", ".rv-headline in the pass state (clamped 24-34px, 700)"],
  ["danger", "danger-soft", "large", ".rv-headline in the fail state"],
  ["warning", "warning-soft", "large", ".rv-headline in the error state"],
];

const MIN = { body: 4.5, large: 3.0, ui: 3.0 };

// --- run --------------------------------------------------------------------

const isLiteral = (name) => name.startsWith("#");
const label = (name) => (isLiteral(name) ? "(literal)" : "--seal-" + name);

let missing = false;
for (const theme of THEMES) {
  for (const [fg, bg] of PAIRS) {
    for (const t of [fg, bg]) {
      if (!isLiteral(t) && !theme.tokens[t]) {
        console.error(`ERROR  --seal-${t} is not defined in style.css :root[data-theme='${theme.name}']`);
        missing = true;
      }
    }
  }
}
if (missing) process.exit(2);

const rows = [];
for (const theme of THEMES) {
  const value = (name) => (isLiteral(name) ? name : theme.tokens[name]);
  for (const [fg, bg, level, where] of PAIRS) {
    const r = ratio(value(fg), value(bg));
    rows.push({ theme: theme.name, fg, bg, fgVal: value(fg), bgVal: value(bg), level, where, r, min: MIN[level], pass: r >= MIN[level] });
  }
}

const w = (s, n) => String(s).padEnd(n);
console.log(`${w("theme", 6)} ${w("foreground", 14)} ${w("", 9)} ${w("background", 12)} ${w("", 9)} ${w("ratio", 8)} ${w("min", 6)} ${w("", 5)} where`);
console.log("-".repeat(130));
for (const r of rows) {
  console.log(
    `${w(r.theme, 6)} ${w(label(r.fg), 14)} ${w(r.fgVal, 9)} ${w(label(r.bg), 12)} ${w(r.bgVal, 9)} ` +
    `${w(r.r.toFixed(2) + ":1", 8)} ${w(r.min.toFixed(1) + ":1", 6)} ${w(r.pass ? "PASS" : "FAIL", 5)} ${r.where}`,
  );
}

const failed = rows.filter((r) => !r.pass);
console.log("-".repeat(130));
console.log(`${rows.length} pairs (${THEMES.length} themes x ${PAIRS.length}) - ${rows.length - failed.length} pass - ${failed.length} fail`);
if (failed.length) {
  console.error("\ncontrast FAIL — fix the token, do not lower the bar:");
  for (const r of failed) console.error(`  [${r.theme}] ${label(r.fg)} on ${label(r.bg)}: ${r.r.toFixed(2)}:1 < ${r.min}:1  (${r.where})`);
  process.exit(1);
}
