// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { receiptSummaryEntries } from "../receipt-summary.js";

test("summary names the blocked receipt's split decision and synthetic clock", () => {
  const text = receiptSummaryEntries({
    tool: "db.execute",
    arguments: { database: "prod", sql: "drop table users" },
    verdict: "BLOCK", deny_kernel: "safety",
    certs: [{ kernel: "safety", verdict: "deny" }, { kernel: "temporal", verdict: "allow" }],
    canonical_request_sha256: "a".repeat(64), args_hash: "b".repeat(64), now: 1000, bypass: false,
  }).map((entry) => entry.text).join("\n");
  assert.match(text, /safety denied it while temporal allowed it/);
  assert.match(text, /fixed synthetic clock, not a wall-clock timestamp/);
  assert.match(text, /bypass is false:.*mediation was not skipped/);
});

test("summary identifies missing fields as absent rather than inferring them", () => {
  const text = receiptSummaryEntries({}).map((entry) => entry.text).join("\n");
  assert.match(text, /tool was absent/);
  assert.match(text, /arguments absent/);
  assert.match(text, /now is absent/);
  assert.match(text, /bypass is absent/);
});
