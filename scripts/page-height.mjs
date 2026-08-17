#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Page-height measurement. Layout claims ("less vertical scrolling") are
// numbers, and a number without a method is a story — so this is the method,
// committed, re-runnable, identical for the before and the after.
//
// Method, exactly:
//   1. serve the repo root over plain HTTP (the page loads app.js as a module
//      and wasm/seal.js as a classic script; file:// blocks the module).
//   2. open the page in headless Chromium at a 1440x900 viewport,
//      deviceScaleFactor 1, default (light or dark) preference untouched.
//   3. wait for `load`, then for #kernel-status to stop saying "checking",
//      then a fixed 600ms settle so app.js has painted.
//   4. read document.documentElement.scrollHeight — the full scrollable
//      document height in CSS pixels, in the page's DEFAULT state: nothing
//      pasted, every <details> in its authored open/closed state.
//
// The reported number is that scrollHeight. Screens-of-scroll = height / 900.
//
// Usage:
//   node scripts/page-height.mjs [url ...]
//   PLAYWRIGHT_PACKAGE=/path/to/node_modules/playwright node scripts/page-height.mjs
//
// Requires Playwright (or the API-compatible patchright) resolvable either
// normally or via PLAYWRIGHT_PACKAGE. Not wired into CI: CI has no browser.

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

const VIEWPORT = { width: 1440, height: 900 };
const SETTLE_MS = 600;
const KERNEL_TIMEOUT_MS = 15000;

function loadBrowser() {
  const candidates = [
    process.env.PLAYWRIGHT_PACKAGE,
    "playwright",
    "playwright-core",
    "patchright",
  ].filter(Boolean);
  for (const spec of candidates) {
    try {
      return require(spec);
    } catch { /* try the next one */ }
  }
  console.error(
    "no Playwright-compatible package found. Install playwright, or point\n" +
    "PLAYWRIGHT_PACKAGE at an existing install:\n" +
    "  PLAYWRIGHT_PACKAGE=/path/to/node_modules/playwright node scripts/page-height.mjs",
  );
  process.exit(2);
}

const urls = process.argv.slice(2);
if (urls.length === 0) {
  urls.push("http://127.0.0.1:8731/index.html", "http://127.0.0.1:8731/tools.html");
}

const { chromium } = loadBrowser();
const browser = await chromium.launch({ headless: true });
const rows = [];

for (const url of urls) {
  const page = await browser.newPage({ viewport: VIEWPORT, deviceScaleFactor: 1 });
  await page.goto(url, { waitUntil: "load" });
  try {
    await page.waitForFunction(
      () => {
        const el = document.getElementById("kernel-status");
        return !el || !/checking/i.test(el.textContent || "");
      },
      { timeout: KERNEL_TIMEOUT_MS },
    );
  } catch {
    console.error(`warning: ${url}: kernel status never settled; measuring anyway`);
  }
  await page.waitForTimeout(SETTLE_MS);
  const m = await page.evaluate(() => ({
    scrollHeight: document.documentElement.scrollHeight,
    bodyFontPx: parseFloat(getComputedStyle(document.body).fontSize),
    contentWidth: document.querySelector("main.wrap")?.getBoundingClientRect().width ?? null,
  }));
  rows.push({ url, ...m, screens: +(m.scrollHeight / VIEWPORT.height).toFixed(2) });
  await page.close();
}

await browser.close();

const pad = (s, n) => (String(s).length > n ? String(s).slice(0, n - 2) + "…" : String(s)).padEnd(n);
console.log(`viewport ${VIEWPORT.width}x${VIEWPORT.height}, metric document.documentElement.scrollHeight (CSS px)`);
console.log(`${pad("url", 46)} ${pad("height", 8)} ${pad("screens", 8)} ${pad("body", 6)} content-width`);
for (const r of rows) {
  console.log(
    `${pad(r.url, 46)} ${pad(r.scrollHeight, 8)} ${pad(r.screens, 8)} ${pad(r.bodyFontPx + "px", 6)} ${r.contentWidth}`,
  );
}
