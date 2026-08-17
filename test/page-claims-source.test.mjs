// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CLAIMS_NOT_PROVES_HTML,
  KERNEL_HASH_SCOPE_LIMIT_TEXT,
  renderPageClaims,
} from "../page-claims.js";
import { receiptSummaryEntries } from "../receipt-summary.js";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

test("defect 4: claims panel and receipt summary read the shared kernel-hash scope sentence from one source", () => {
  const seen = [{ innerHTML: "" }, { innerHTML: "" }];
  renderPageClaims({ querySelectorAll: () => seen });
  for (const node of seen) {
    assert.equal(node.innerHTML, CLAIMS_NOT_PROVES_HTML);
    assert.ok(node.innerHTML.includes(KERNEL_HASH_SCOPE_LIMIT_TEXT));
  }

  const summaryText = receiptSummaryEntries({
    kernel_identity: { wasm_sha256: "e".repeat(64) },
  }).at(-1).text;
  assert.ok(summaryText.includes(KERNEL_HASH_SCOPE_LIMIT_TEXT));
});

test("defect 4: both browser pages keep the shared claims placeholder instead of inline drift-prone prose", () => {
  for (const file of ["index.html", "tools.html"]) {
    const text = readFileSync(resolve(ROOT, file), "utf8");
    assert.match(text, /data-claims-not-proves/);
  }
});
