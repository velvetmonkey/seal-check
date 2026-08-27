// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { extname, join, normalize } from "node:path";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const ROOT = new URL("..", import.meta.url);

const MIME = {
  ".css": "text/css",
  ".html": "text/html",
  ".js": "text/javascript",
  ".json": "application/json",
  ".wasm": "application/wasm",
};

function startStaticServer() {
  const root = join(ROOT.pathname);
  const server = createServer(async (request, response) => {
    const pathname = decodeURIComponent(new URL(request.url, "http://127.0.0.1").pathname);
    const file = normalize(join(root, pathname === "/" ? "index.html" : pathname.slice(1)));
    if (!file.startsWith(root)) {
      response.writeHead(404).end();
      return;
    }
    try {
      const body = await readFile(file);
      response.writeHead(200, { "Content-Type": MIME[extname(file)] || "application/octet-stream" }).end(body);
    } catch {
      response.writeHead(404).end();
    }
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({
    server,
    url: `http://127.0.0.1:${server.address().port}/`,
  })));
}

test("CSP refuses cross-origin requests while same-origin receipt, wasm, and tamper checks work", async (t) => {
  let playwright;
  try {
    playwright = require("playwright");
  } catch (error) {
    t.skip(`Playwright is unavailable: ${error.message}`);
    return;
  }

  const { server, url } = await startStaticServer();
  t.after(() => server.close());
  const browser = await playwright.chromium.launch({ headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const refusals = [];
  page.on("console", (message) => {
    if (message.type() === "error" && /Refused to connect/.test(message.text())) refusals.push(message.text());
  });

  await page.goto(url, { waitUntil: "networkidle" });
  await page.locator("#kernel-status").waitFor({ state: "visible" });
  await page.waitForFunction(
    () => document.querySelector("#kernel-status")?.textContent.includes("kernel verified"),
    null,
    { timeout: 10000 },
  );

  const boot = await page.locator("#kernel-status").textContent();
  assert.match(boot, /kernel verified/, `same-origin wasm did not load: ${boot}`);
  assert.equal(await page.locator("#rv-example-label").isVisible(), true, "same-origin example receipt did not load");
  assert.equal(await page.locator("#rv-verdict").textContent(), "ALLOWED");
  assert.equal((await page.locator("#ident-sha").textContent()).trim().length, 64, "wasm hash was not rendered");

  const result = await page.evaluate(async () => {
    try {
      await fetch("https://cross-origin.invalid/seal-check-negative-control");
      return { status: "resolved" };
    } catch (error) {
      return { status: "rejected", name: error.name, message: error.message };
    }
  });
  assert.equal(result.status, "rejected");
  assert.ok(refusals.length > 0, "the browser emitted no observable CSP refusal");
  console.log(`CSP refusal: ${refusals[0]}`);

  const receipt = await readFile(new URL("../examples/allow.receipt.json", import.meta.url), "utf8");
  const tampered = receipt.replace('"verdict": "ALLOW"', '"verdict": "BLOCK"');
  await page.locator("#paste-input").fill(tampered);
  await page.locator("#rv-headline").filter({ hasText: "does NOT check out" }).waitFor();
  assert.equal(await page.locator("#rv-verdict").textContent(), "REFUSED");
  console.log("Still works: example ALLOWED, wasm verified, tampered receipt REFUSED.");
});
