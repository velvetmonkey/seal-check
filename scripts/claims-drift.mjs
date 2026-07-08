#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Claims drift guard. The claim / non-claim block is credibility-critical and
// lives on three surfaces; this asserts the mirrors are verbatim copies of the
// canonical block in docs/LIMITATIONS.md, so drift fails loudly instead of
// shipping silently.
//
// Mechanism: each surface wraps the block in stable markers
// (<!-- claims:begin --> ... <!-- claims:end -->). The marked region is
// extracted, any HTML wrapper stripped, whitespace normalised per line,
// and compared for exact equality with the canonical block.
//
// Exit codes: 0 in sync · 1 drift (diff printed) · 2 markers missing/malformed.
// Node only, no dependencies. Run: node scripts/claims-drift.mjs
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BEGIN = "<!-- claims:begin -->";
const END = "<!-- claims:end -->";

const CANONICAL = "docs/LIMITATIONS.md";
const MIRRORS = ["README.md", "docs/THREAT-MODEL.md"];

function extract(file) {
  let text;
  try {
    text = readFileSync(resolve(ROOT, file), "utf8");
  } catch (e) {
    console.error(`ERROR  ${file}: ${e.message}`);
    process.exit(2);
  }
  const i = text.indexOf(BEGIN);
  const j = text.indexOf(END);
  if (i === -1 || j === -1 || j < i) {
    console.error(`ERROR  ${file}: claims markers missing or malformed (need ${BEGIN} ... ${END})`);
    process.exit(2);
  }
  if (text.indexOf(BEGIN, i + 1) !== -1 || text.indexOf(END, j + 1) !== -1) {
    console.error(`ERROR  ${file}: multiple claims marker pairs — exactly one region per file`);
    process.exit(2);
  }
  return text.slice(i + BEGIN.length, j);
}

// Per-line trim + drop blanks; strip the index.html <pre> wrapper. The claim
// text itself contains no HTML entities or tags, so tag-stripping is safe.
function normalise(block) {
  return block
    .replace(/<pre[^>]*>/g, "")
    .replace(/<\/pre>/g, "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .join("\n");
}

const canonical = normalise(extract(CANONICAL));
if (!canonical) {
  console.error(`ERROR  ${CANONICAL}: canonical claims block is empty`);
  process.exit(2);
}

let drift = false;
for (const file of MIRRORS) {
  const got = normalise(extract(file));
  if (got === canonical) {
    console.log(`PASS  ${file} matches ${CANONICAL}`);
    continue;
  }
  drift = true;
  console.error(`FAIL  ${file} diverges from ${CANONICAL}:`);
  const a = canonical.split("\n");
  const b = got.split("\n");
  for (let k = 0; k < Math.max(a.length, b.length); k++) {
    if (a[k] !== b[k]) {
      console.error(`  line ${k + 1}:`);
      console.error(`    canonical : ${a[k] ?? "<missing>"}`);
      console.error(`    ${file.padEnd(10)}: ${b[k] ?? "<missing>"}`);
    }
  }
}

if (drift) {
  console.error("\nCLAIMS DRIFT — edit docs/LIMITATIONS.md first, then mirror verbatim.");
  process.exit(1);
}
console.log("claims block in sync across all surfaces");
