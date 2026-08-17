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
// Thresholds (WCAG 2.1):
//   body   >= 4.5:1  (1.4.3, normal-size text)
//   large  >= 3.0:1  (1.4.3, >=18.66px bold or >=24px regular)
//   ui     >= 3.0:1  (1.4.11, borders and other non-text UI boundaries)
//
// Exit 0 when every pair passes, 1 when any pair fails, 2 on a missing token.
// Node only, no dependencies. Run: node scripts/contrast.mjs

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CSS = readFileSync(resolve(ROOT, "style.css"), "utf8");

// --- token extraction -------------------------------------------------------

// Only the :root block; a token redefined elsewhere would be a different scope.
const rootBlock = CSS.slice(CSS.indexOf(":root {"), CSS.indexOf("}", CSS.indexOf(":root {")));
const TOKENS = Object.create(null);
for (const m of rootBlock.matchAll(/--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8})\s*;/g)) {
  TOKENS[m[1]] = m[2];
}

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
// A name resolves to the --name custom property; a literal "#rrggbb" is a
// colour hardcoded outside the palette (currently only the generated badge
// SVG, which is copied off the page and so cannot use page tokens).

const PAIRS = [
  // body copy
  ["ink", "bg", "body", "body copy, h1/h2/h3, .rv-subline, .rv-limit p, table cells"],
  ["ink", "panel", "body", ".claim p, .card-attack, .tool-fold > summary, textarea"],
  ["ink", "panel2", "body", "button label"],
  ["ink", "code-bg", "body", "<code> inside body copy"],
  ["muted", "bg", "body", ".muted, .privacy, th, details summary, .ident dd, .rv-table .rvt-detail"],
  ["muted", "panel", "body", ".card-why, .tool-fold body copy, .copy-fallback"],
  ["muted", "code-bg", "body", "<code> inside .muted paragraphs"],
  ["muted", "bad-bg", "body", ".rv-table tr.rvt-row-fail td.rvt-detail"],
  ["accent", "bg", "body", "links, .spec-ref, .spec-id"],
  ["accent", "panel", "body", ".card-lens on a card, links inside .tool-fold"],

  // verdict + state text (mono, 13px+, so held to the body threshold, not large)
  ["ok", "bg", "body", ".v-allow, .rvt-pass, .determinism.ok, .card-result.ok, .rv-ok"],
  ["ok", "panel", "body", ".card-result.ok inside a card, .claim.proves h3"],
  ["ok", "ok-bg", "body", ".pill-ok, .lab-ok, .rv-banner.ok .rv-headline"],
  ["bad", "bg", "body", ".v-block, .rvt-fail, .rv-fails li, .rv-bad, .error"],
  ["bad", "panel", "body", ".card-result.bad inside a card"],
  ["bad", "bad-bg", "body", ".pill-bad, .rv-banner.bad text, .rvt-row-fail state cell"],
  ["warn", "bg", "body", ".v-error, .rvt-skip, .reason.warn"],
  ["warn", "panel", "body", ".claim.notproves h3 on a panel"],
  ["warn", "warn-bg", "body", ".lab-asserted, .rv-banner.warn .rv-headline"],
  ["ink", "ok-bg", "body", ".rv-banner.ok .rv-subline"],
  ["ink", "bad-bg", "body", ".rv-banner.bad .rv-subline, .rvt-row-fail td"],
  ["ink", "warn-bg", "body", ".rv-banner.warn .rv-subline"],

  // the one reversed-out control
  ["primary-ink", "primary-bg", "body", "button.primary label"],

  // non-text UI boundaries
  ["line", "bg", "ui", "section rules, table rules, card/panel/textarea/button borders"],
  ["line", "panel", "ui", "borders of elements sitting on a panel"],
  ["line", "panel2", "ui", "button border"],
  ["accent", "bg", "ui", "button:hover border, focus ring"],
  ["ok-line", "bg", "ui", ".pill-ok, .claim.proves, .rv-banner.ok, .lab-ok borders"],
  ["ok-line", "ok-bg", "ui", "the same borders against their own fill"],
  ["bad-line", "bg", "ui", ".pill-bad, .rv-banner.bad borders"],
  ["bad-line", "bad-bg", "ui", "the same borders against their own fill"],
  ["warn-line", "bg", "ui", ".claim.notproves, .rv-banner.warn, .lab-asserted borders"],
  ["warn-line", "warn-bg", "ui", "the same borders against their own fill"],
  ["primary-line", "bg", "ui", "button.primary border"],

  // the generated badge SVG (app.js badgeSvg(); self-contained by design)
  ["#ffffff", "#3a3a44", "body", "badge label text on the badge's left plate"],
  ["#ffffff", "#0a7d61", "body", "badge sha text on the badge's right plate"],

  // large text (>=24px): the re-check headline
  ["ok", "ok-bg", "large", ".rv-headline in the pass state (clamped 26-38px, 700)"],
  ["bad", "bad-bg", "large", ".rv-headline in the fail state"],
  ["warn", "warn-bg", "large", ".rv-headline in the error state"],
];

const MIN = { body: 4.5, large: 3.0, ui: 3.0 };

// --- run --------------------------------------------------------------------

const isLiteral = (name) => name.startsWith("#");
const label = (name) => (isLiteral(name) ? "(literal)" : "--" + name);
const value = (name) => (isLiteral(name) ? name : TOKENS[name]);

let missing = false;
for (const [fg, bg] of PAIRS) {
  for (const t of [fg, bg]) {
    if (!isLiteral(t) && !TOKENS[t]) {
      console.error(`ERROR  --${t} is not defined in style.css :root`);
      missing = true;
    }
  }
}
if (missing) process.exit(2);

const rows = PAIRS.map(([fg, bg, level, where]) => {
  const r = ratio(value(fg), value(bg));
  return { fg, bg, level, where, r, min: MIN[level], pass: r >= MIN[level] };
});

const w = (s, n) => String(s).padEnd(n);
console.log(`${w("foreground", 14)} ${w("", 9)} ${w("background", 12)} ${w("", 9)} ${w("ratio", 8)} ${w("min", 6)} ${w("", 5)} where`);
console.log("-".repeat(120));
for (const r of rows) {
  console.log(
    `${w(label(r.fg), 14)} ${w(value(r.fg), 9)} ${w(label(r.bg), 12)} ${w(value(r.bg), 9)} ` +
    `${w(r.r.toFixed(2) + ":1", 8)} ${w(r.min.toFixed(1) + ":1", 6)} ${w(r.pass ? "PASS" : "FAIL", 5)} ${r.where}`,
  );
}

const failed = rows.filter((r) => !r.pass);
console.log("-".repeat(120));
console.log(`${rows.length} pairs · ${rows.length - failed.length} pass · ${failed.length} fail`);
if (failed.length) {
  console.error("\ncontrast FAIL — fix the token, do not lower the bar:");
  for (const r of failed) console.error(`  ${label(r.fg)} on ${label(r.bg)}: ${r.r.toFixed(2)}:1 < ${r.min}:1  (${r.where})`);
  process.exit(1);
}
