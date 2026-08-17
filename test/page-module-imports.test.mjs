// SPDX-License-Identifier: Apache-2.0
// The page's ES-module graph must not contain an import that its static files
// do not ship. A missing import prevents app.js from evaluating at all.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const ROOT = resolve(import.meta.dirname, "..");

test("defect 1: every local module imported by app.js is shipped", () => {
  const source = readFileSync(resolve(ROOT, "app.js"), "utf8");
  const imports = [...source.matchAll(/from\s+["'](\.\/[^"']+)["']/g)].map((match) => match[1]);
  assert.ok(imports.length > 0, "app.js should have local module imports to check");
  for (const specifier of imports) {
    assert.equal(existsSync(resolve(ROOT, specifier)), true, `missing module imported by app.js: ${specifier}`);
  }
});
