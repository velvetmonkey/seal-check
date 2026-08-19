// SPDX-License-Identifier: Apache-2.0
// Test-fixture temp directories. Removed on process exit, including
// assertion failures. Set KEEP_TMP=1 to retain them as evidence.
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const owned = new Set();

function keep() {
  const value = process.env.KEEP_TMP;
  return value === "1" || value === "true";
}

function chmodTree(dir) {
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    return;
  }
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory() && !entry.isSymbolicLink()) chmodTree(full);
    else {
      try { fs.chmodSync(full, 0o600); } catch { /* best-effort */ }
    }
  }
}

function rm(dir) {
  if (keep() || !dir) return;
  try {
    chmodTree(dir);
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
}

function cleanup() {
  for (const dir of owned) rm(dir);
  owned.clear();
}

process.on("exit", cleanup);

function tmpdir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  owned.add(dir);
  return dir;
}

module.exports = { tmpdir, cleanup, keep };
