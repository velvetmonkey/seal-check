// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { createSocket } from "node:dgram";
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

test("CSP blocks cross-origin requests, declares WebRTC blocking, and observes enforcement when available", async (t) => {
  let playwright;
  try {
    playwright = require("playwright");
  } catch (error) {
    t.skip(`Playwright is unavailable: ${error.message}`);
    return;
  }

  const { server, url } = await startStaticServer();
  t.after(() => server.close());
  const browser = await playwright.chromium.launch({
    headless: true,
    executablePath: process.env.CHROME_FOR_TESTING || undefined,
  });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const refusals = [];
  const consoleErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push(message.text());
      if (/Refused to connect/.test(message.text())) refusals.push(message.text());
    }
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
  const csp = await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute("content");
  assert.match(csp || "", /(?:^|;\s*)webrtc 'block'(?:\s*;|$)/, "the page no longer declares WebRTC blocking");

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

  const sink = createSocket("udp4");
  const packets = [];
  sink.on("message", (message, remote) => packets.push({ bytes: message.length, address: remote.address, port: remote.port }));
  await new Promise((resolve) => sink.bind(0, "127.0.0.1", resolve));
  t.after(() => sink.close());
  const sinkPort = sink.address().port;
  const webrtcResult = await page.evaluate(async (port) => {
    try {
      const pc = new RTCPeerConnection({ iceServers: [{ urls: `stun:127.0.0.1:${port}` }] });
      pc.createDataChannel("seal-check-negative-control");
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await new Promise((resolve) => {
        if (pc.iceGatheringState === "complete") return resolve();
        pc.onicegatheringstatechange = () => pc.iceGatheringState === "complete" && resolve();
        setTimeout(resolve, 1000);
      });
      const result = {
        status: pc.iceGatheringState === "complete" && !pc.localDescription.sdp.includes("a=candidate:") ? "blocked" : "not-blocked",
        connection: pc.connectionState,
        ice: pc.iceConnectionState,
      };
      pc.close();
      return result;
    } catch (error) {
      return { status: "rejected", name: error.name, message: error.message };
    }
  }, sinkPort);
  await new Promise((resolve) => setTimeout(resolve, 250));
  if (webrtcResult.status === "blocked" || webrtcResult.status === "rejected") {
    assert.equal(packets.length, 0, `WebRTC sink received ${JSON.stringify(packets)}`);
  }
  console.log(`WebRTC browser result: ${JSON.stringify(webrtcResult)}`);
  console.log(`WebRTC browser errors: ${JSON.stringify(consoleErrors)}`);
  console.log(`WebRTC sink: ${packets.length} UDP packets received. Browser enforcement: ${webrtcResult.status}.`);

  const receipt = await readFile(new URL("../examples/allow.receipt.json", import.meta.url), "utf8");
  const tampered = receipt.replace('"verdict": "ALLOW"', '"verdict": "BLOCK"');
  await page.locator("#paste-input").fill(tampered);
  await page.locator("#rv-headline").filter({ hasText: "does NOT check out" }).waitFor();
  assert.equal(await page.locator("#rv-verdict").textContent(), "REFUSED");
  console.log("Still works: example ALLOWED, wasm verified, tampered receipt REFUSED.");
});
