// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { KERNEL_HASH_SCOPE_LIMIT_TEXT } from "../page-claims.js";
import {
  clearReceiptSummary,
  receiptSummaryEntries,
  renderReceiptSummary,
} from "../receipt-summary.js";

class FakeNode {
  constructor(tagName, ownerDocument, text = "") {
    this.tagName = tagName;
    this.ownerDocument = ownerDocument;
    this.textContent = text;
    this.className = "";
    this.children = [];
  }

  append(...items) {
    for (const item of items) this.children.push(item);
  }

  appendChild(item) {
    this.children.push(item);
  }

  replaceChildren(...items) {
    this.children = [...items];
  }
}

class FakeDocument {
  createElement(tag) {
    return new FakeNode(tag, this);
  }

  createTextNode(text) {
    return { nodeType: 3, textContent: text };
  }
}

function joinedText(receipt) {
  return receiptSummaryEntries(receipt).map((entry) => entry.text).join("\n");
}

test("defect 1: split decision with a contrary cert is marked as a conflict", () => {
  const text = joinedText({
    tool: "db.execute",
    arguments: { database: "prod", sql: "drop table users" },
    verdict: "BLOCK",
    deny_kernel: "safety",
    certs: [{ kernel: "safety", verdict: "deny" }, { kernel: "temporal", verdict: "allow" }],
    canonical_request_sha256: "a".repeat(64),
    args_hash: "b".repeat(64),
    now: 1000,
    bypass: false,
    kernel_identity: { wasm_sha256: "c".repeat(64) },
  });
  assert.match(text, /This is a split decision: safety denied it while temporal allowed it; the BLOCK headline comes from safety\./);
  assert.match(text, /CONFLICT: verdict says BLOCK but per-gate results include temporal \(allow\)\./);
});

test("defect 1: summary marks a top-level verdict contradiction instead of smoothing it", () => {
  const text = joinedText({
    verdict: "ALLOW",
    deny_kernel: null,
    certs: [{ kernel: "safety", verdict: "deny" }],
  });
  assert.match(text, /CONFLICT: verdict says ALLOW but per-gate results include safety \(deny\)\./);
});

test("contradiction rule catches a BLOCK headline whose named denying kernel allowed", () => {
  const text = joinedText({
    verdict: "BLOCK",
    deny_kernel: "safety",
    certs: [{ kernel: "safety", verdict: "allow" }, { kernel: "temporal", verdict: "deny" }],
  });
  assert.match(text, /CONFLICT: verdict says BLOCK but per-gate results include safety \(allow\)\./);
  assert.match(text, /CONFLICT: deny_kernel says safety but the denying per-gate results are temporal\./);
});

test("contradiction rule catches an ALLOW headline amid disagreeing certs", () => {
  const text = joinedText({
    verdict: "ALLOW",
    deny_kernel: null,
    certs: [{ kernel: "safety", verdict: "allow" }, { kernel: "temporal", verdict: "deny" }],
  });
  assert.match(text, /CONFLICT: verdict says ALLOW but per-gate results include temporal \(deny\)\./);
});

test("summary reports missing fields as absent instead of inferring them", () => {
  const text = joinedText({});
  assert.match(text, /tool was absent/);
  assert.match(text, /arguments absent/);
  assert.match(text, /now is absent/);
  assert.match(text, /bypass is absent/);
});

test("defect 3: summary narrows the non-certification sentence to the kernel hash field it actually reads", () => {
  const text = joinedText({
    kernel_identity: { wasm_sha256: "d".repeat(64) },
  });
  assert.match(text, /kernel_identity\.wasm_sha256 is d{64}\. It names the kernel hash recorded in this receipt\./);
  assert.match(text, new RegExp(KERNEL_HASH_SCOPE_LIMIT_TEXT.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(text, /The sha256 verifies which binary ran\./);
});

test("defect 2: clearReceiptSummary removes stale summary lines before a refusal path can leave them behind", () => {
  const doc = new FakeDocument();
  const container = new FakeNode("div", doc);
  container.children.push({ stale: true });
  renderReceiptSummary(container, {
    tool: "x",
    arguments: "<b>hello</b><script>window.__pwned=1</script>",
  });

  assert.equal(container.children.length, 6);
  const firstLine = container.children[0];
  const derivedText = firstLine.children[1];
  assert.equal(derivedText.textContent.includes("<script>window.__pwned=1</script>"), true);
  assert.equal(Object.prototype.hasOwnProperty.call(derivedText, "innerHTML"), false);

  clearReceiptSummary(container);
  assert.equal(container.children.length, 0);
});
