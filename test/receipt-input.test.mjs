// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { pastedReceiptDocumentOrError } from "../receipt-input.js";

test("defect 2: empty pasted input is a visible refusal, not a silent no-op", () => {
  assert.deepEqual(pastedReceiptDocumentOrError("   "), {
    ok: false,
    error: "receipt refused: empty document.",
  });
});

test("pasted helper decodes base64url receipt links and raw blobs", () => {
  assert.deepEqual(
    pastedReceiptDocumentOrError("https://example.invalid/#receipt=eyJmb28iOiJiYXIifQ"),
    { ok: true, document: "{\"foo\":\"bar\"}" },
  );
  assert.deepEqual(
    pastedReceiptDocumentOrError("eyJmb28iOiJiYXIifQ"),
    { ok: true, document: "{\"foo\":\"bar\"}" },
  );
});

test("bare encoded receipt fixtures decode without changing their document bytes", async () => {
  const { readFileSync } = await import("node:fs");
  for (const fixture of ["host-v2-block.receipt.json", "host-v3-block.receipt.json", "unparseable-block.receipt.json"]) {
    const document = readFileSync(new URL(`fixtures/${fixture}`, import.meta.url), "utf8");
    const encoded = Buffer.from(document, "utf8").toString("base64url");
    assert.deepEqual(pastedReceiptDocumentOrError(encoded), { ok: true, document }, fixture);
    assert.deepEqual(pastedReceiptDocumentOrError(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, "=")), { ok: true, document }, `${fixture} padded`);
  }
});

test("bare identifiers remain literal pasted text", () => {
  for (const document of ["TestCase123", "smrgadeltacodec", "0123456789abcdef0123456789abcdef", "abcdefgh"]) {
    assert.deepEqual(pastedReceiptDocumentOrError(document), { ok: true, document });
  }
});

test("raw JSON containing a receipt URL preserves the entire original document", () => {
  const raw = '  {"tool":"fetch","arguments":{"url":"https://example.invalid/#receipt=eyJmb28iOiJiYXIifQ"}}\n';
  assert.deepEqual(pastedReceiptDocumentOrError(raw), { ok: true, document: raw });
});

test("complete receipt with an embedded link is preserved", async () => {
  const { readFileSync } = await import("node:fs");
  const receipt = JSON.parse(readFileSync(new URL("fixtures/host-v2-block.receipt.json", import.meta.url), "utf8"));
  receipt.arguments.url = "https://example.invalid/#receipt=eyJmb28iOiJiYXIifQ";
  const raw = JSON.stringify(receipt);
  assert.deepEqual(pastedReceiptDocumentOrError(raw), { ok: true, document: raw });
  const { verifyReceipt } = await import("../receipt.js");
  assert.equal((await verifyReceipt(raw)).formatOk, false, "changed arguments still fail receipt binding");
});

test("only whole links and fragments decode; surrounding prose and trailing junk do not", () => {
  const fragment = "#receipt=eyJmb28iOiJiYXIifQ";
  assert.equal(pastedReceiptDocumentOrError(fragment).document, '{"foo":"bar"}');
  for (const raw of [`see https://example.invalid/${fragment}`, `https://example.invalid/${fragment}&extra=1`, `${fragment}!`, `{"broken":"${fragment}"`]) {
    assert.equal(pastedReceiptDocumentOrError(raw).document, raw);
  }
  assert.equal(pastedReceiptDocumentOrError("#receipt=a").ok, false);
});

test("receipt link adjacent to JSON punctuation preserves the outer document", () => {
  const link = "https://example.invalid/#receipt=eyJmb28iOiJiYXIifQ";
  for (const document of [JSON.stringify({ link, verdict: "BLOCK" }), JSON.stringify([link, {}]), JSON.stringify(link)]) {
    assert.deepEqual(pastedReceiptDocumentOrError(document), { ok: true, document });
  }
});

test("only a whole receipt URL or fragment is decoded", () => {
  const fragment = "#receipt=eyJmb28iOiJiYXIifQ";
  assert.deepEqual(pastedReceiptDocumentOrError(fragment), { ok: true, document: '{"foo":"bar"}' });
  for (const document of [`prefix ${fragment}`, `https://example.invalid/${fragment}&extra=1`]) {
    assert.deepEqual(pastedReceiptDocumentOrError(document), { ok: true, document });
  }
});

// Exercise the actual app handlers with a minimal DOM, retaining the production
// error renderer and replacing only boot/UI dependencies and the verifier sink.
async function inputPage() {
  const { readFileSync } = await import("node:fs");
  const { runInNewContext } = await import("node:vm");
  const nodes = new Map();
  function node() {
    const classes = new Set(["hidden"]);
    return {
      value: "", textContent: "", listeners: {},
      classList: { add: (s) => classes.add(s), remove: (s) => classes.delete(s), contains: (s) => classes.has(s) },
      addEventListener(type, fn) { this.listeners[type] = fn; },
      replaceChildren() { this.textContent = ""; },
      append() {},
    };
  }
  const get = (id) => {
    if (!nodes.has(id)) nodes.set(id, node());
    return nodes.get(id);
  };
  const processed = [], decoded = [];
  const context = {
    document: { getElementById: get, querySelectorAll: () => [], querySelector: () => null, body: node(), createElement: node },
    window: { addEventListener() {} }, URL, TextEncoder, clearTimeout, setTimeout,
    renderPageClaims() {}, installTooltipBehavior() {},
    clearReceiptSummary: (n) => n.replaceChildren(),
    pastedReceiptDocumentOrError(raw) { decoded.push(raw); return pastedReceiptDocumentOrError(raw); },
    recordDocument: (raw) => processed.push(raw),
  };
  const source = readFileSync(new URL("../app.js", import.meta.url), "utf8")
    .replace(/^import\s+[\s\S]*?\s+from\s+"[^"]+";\n/gm, "")
    .replaceAll("import.meta.url", JSON.stringify(new URL("../app.js", import.meta.url).href))
    .replace(/\ninit\(\);\s*$/, "\nboot = async () => {}; renderClassifiedReceiptDocument = async (raw) => recordDocument(raw); init();");
  runInNewContext(source, context);
  return { get, processed, decoded, paste: context.checkPasted };
}

const INPUT_LIMIT = 1024 * 1024;
function assertSizeRefusal(page) {
  assert.match(page.get("rv-summary").textContent, /exceeds.*1048576.*bytes/i);
  assert.equal(page.get("rv-result").classList.contains("hidden"), false);
  assert.equal(page.get("rv-banner").className, "rv-banner bad");
  assert.equal(page.get("rv-json").textContent, "");
  assert.equal(page.decoded.length, 0, "refuse before decoding or parsing");
  assert.equal(page.processed.length, 0, "refuse before verification or document rendering");
}

test("oversized pasted receipt is refused before processing, including UTF-8", async () => {
  for (const raw of ['{}' + " ".repeat(INPUT_LIMIT - 1), "é".repeat(INPUT_LIMIT / 2 + 1), "😀".repeat(INPUT_LIMIT / 4 + 1)]) {
    const page = await inputPage();
    page.get("paste-input").value = raw;
    await page.paste();
    assertSizeRefusal(page);
  }
});

test("oversized uploads are refused before file.text for both fields", async () => {
  for (const [fileId, textId] of [["receipt-file", "paste-input"], ["signer-file", "signer-key"]]) {
    const page = await inputPage();
    page.get(textId).value = "previous";
    let reads = 0;
    await page.get(fileId).listeners.change({ target: { files: [{ size: INPUT_LIMIT + 1, async text() { reads++; return "{}"; } }] } });
    assert.equal(reads, 0, "oversized file must never be read");
    assert.equal(page.get(textId).value, "previous");
    assertSizeRefusal(page);
  }
});

test("normal and exact-ceiling pastes preserve received documents", async () => {
  const { readFileSync } = await import("node:fs");
  const fixture = readFileSync(new URL("fixtures/host-v3-block.receipt.json", import.meta.url), "utf8");
  for (const raw of [fixture, "{}" + " ".repeat(INPUT_LIMIT - 2), '"' + "é".repeat((INPUT_LIMIT - 2) / 2) + '"']) {
    const page = await inputPage();
    page.get("paste-input").value = raw;
    await page.paste();
    assert.deepEqual(page.processed, [raw]);
  }
});

test("normal and exact-ceiling files retain per-field wiring and trimming", async () => {
  const { readFileSync } = await import("node:fs");
  const fixture = readFileSync(new URL("fixtures/host-v3-block.receipt.json", import.meta.url), "utf8");
  for (const [fileId, textId] of [["receipt-file", "paste-input"], ["signer-file", "signer-key"]]) {
    for (const raw of [fixture, "{}" + " ".repeat(INPUT_LIMIT - 2)]) {
      const page = await inputPage();
      page.get("paste-input").value = fixture;
      let reads = 0;
      await page.get(fileId).listeners.change({ target: { files: [{ size: Buffer.byteLength(raw), async text() { reads++; return raw; } }] } });
      assert.equal(reads, 1);
      assert.equal(page.get(textId).value, raw.trim());
      assert.deepEqual(page.processed, [fileId === "receipt-file" ? raw.trim() : fixture]);
    }
  }
});

for (const [name, bytes] of [
  ["invalid continuation", [0xc3, 0x28]],
  ["overlong encoding", [0xc0, 0xaf]],
  ["lone surrogate", [0xed, 0xa0, 0x80]],
]) {
  test(`pasted text, link and uploaded encoded file refuse ${name} by name and recover`, async () => {
    const encoded = Buffer.concat([Buffer.from('{"text":"'), Buffer.from(bytes), Buffer.from('"}')]).toString("base64url");
    for (const raw of [encoded, `  https://example.invalid/#receipt=${encoded} \n`]) {
      assert.deepEqual(pastedReceiptDocumentOrError(raw), { ok: false, error: "receipt payload is not valid UTF-8" });
      const page = await inputPage();
      page.get("paste-input").value = raw;
      await page.paste();
      assert.equal(page.get("rv-summary").textContent, "receipt payload is not valid UTF-8");
      assert.deepEqual(page.processed, []);
      page.get("paste-input").value = Buffer.from('{"text":"😀 Ελληνικά"}').toString("base64url");
      await page.paste();
      assert.deepEqual(page.processed, ['{"text":"😀 Ελληνικά"}']);
    }
    const page = await inputPage();
    await page.get("receipt-file").listeners.change({ target: { files: [{ size: encoded.length, async text() { return encoded; } }] } });
    assert.equal(page.get("rv-summary").textContent, "receipt payload is not valid UTF-8");
    assert.deepEqual(page.processed, []);
  });
}

test("valid Unicode, BOM and padded receipts retain the transport contract", () => {
  const document = '{"text":"😀 Ελληνικά"}';
  for (const text of [document, '\ufeff' + document]) {
    const encoded = Buffer.from(text).toString("base64url");
    // A bare blob is selected by its JSON-leading bytes; BOM blobs use a link.
    assert.deepEqual(pastedReceiptDocumentOrError(` \nhttps://example.invalid/#receipt=${encoded} \t`), { ok: true, document });
    const padded = encoded.padEnd(Math.ceil(encoded.length / 4) * 4, "=");
    assert.deepEqual(pastedReceiptDocumentOrError(`#receipt=${padded}`), { ok: true, document });
  }
});

test("one changed signed-string byte is refused on all five transports", async () => {
  const { readFileSync } = await import("node:fs");
  const { b64urlToStr, decodeReceiptDocument } = await import("../receipt.js");
  const { classifyReceiptFragment } = await import("../fragment-classifier.js");
  const bytes = readFileSync(new URL("fixtures/host-v2-block.receipt.json", import.meta.url));
  const index = bytes.indexOf("seal-shell-demo");
  assert.ok(index > 0, "real signed_config payload string exists");
  bytes[index] = 0xc3;
  const encoded = bytes.toString("base64url");
  const message = "receipt payload is not valid UTF-8";
  assert.throws(() => b64urlToStr(encoded), { message });
  const previousLocation = globalThis.location;
  try {
    globalThis.location = { hash: "#receipt=" + encoded };
    assert.throws(() => decodeReceiptDocument(), { message });
  } finally { globalThis.location = previousLocation; }
  assert.deepEqual(pastedReceiptDocumentOrError(encoded), { ok: false, error: message });
  assert.deepEqual(pastedReceiptDocumentOrError(`https://example.invalid/#receipt=${encoded}`), { ok: false, error: message });
  assert.deepEqual(classifyReceiptFragment("#receipt=" + encoded), { kind: "unparseable", error: message });
  const page = await inputPage();
  await page.get("receipt-file").listeners.change({ target: { files: [{ size: encoded.length, async text() { return encoded; } }] } });
  assert.equal(page.get("rv-summary").textContent, message);
  assert.deepEqual(page.processed, []);
  const valid = readFileSync(new URL("fixtures/host-v2-block.receipt.json", import.meta.url), "utf8");
  page.get("paste-input").value = valid;
  await page.paste();
  assert.deepEqual(page.processed, [valid]);
});

test("largest real fixture stays exact through shared decoder, fragment, paste and upload", async () => {
  const { readFileSync } = await import("node:fs");
  const { b64urlToStr, decodeReceiptDocument } = await import("../receipt.js");
  const { classifyReceiptFragment } = await import("../fragment-classifier.js");
  const document = readFileSync(new URL("fixtures/host-v3-block.receipt.json", import.meta.url), "utf8");
  assert.equal(Buffer.byteLength(document), 7605);
  const encoded = Buffer.from(document).toString("base64url");
  assert.equal(b64urlToStr(encoded), document);
  const previousLocation = globalThis.location;
  try {
    globalThis.location = { hash: "#receipt=" + encoded };
    assert.equal(decodeReceiptDocument(), document);
  } finally { globalThis.location = previousLocation; }
  assert.equal(classifyReceiptFragment("#receipt=" + encoded).document, document);
  assert.deepEqual(pastedReceiptDocumentOrError(encoded), { ok: true, document });
  assert.deepEqual(pastedReceiptDocumentOrError(` \nhttps://example.invalid/#receipt=${encoded} \t`), { ok: true, document });
  const page = await inputPage();
  await page.get("receipt-file").listeners.change({ target: { files: [{ size: encoded.length, async text() { return encoded; } }] } });
  assert.deepEqual(page.processed, [document]);
});
