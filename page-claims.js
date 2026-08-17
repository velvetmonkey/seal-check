// SPDX-License-Identifier: Apache-2.0

export const KERNEL_HASH_SCOPE_LIMIT_TEXT =
  "That field does not, by itself, describe your whole MCP server, your transport, your tool implementations, or whether your deployment routes calls through this gate.";

export const CLAIMS_NOT_PROVES_HTML = [
  "This page shows one kernel binary hash in <code>kernel_identity.wasm_sha256</code>.",
  KERNEL_HASH_SCOPE_LIMIT_TEXT,
  "It does <strong>not</strong> prove the axioms or the Lean proofs themselves.",
  "No third party certifies anything here.",
  "In particular <strong>ARIA certifies nothing</strong>, no ARIA endorsement, outcome, affiliation, or status is claimed or implied.",
  "This is not an endorsement and not a trustworthiness badge for your server.",
].join(" ");

export function renderPageClaims(root = document) {
  for (const node of root.querySelectorAll("[data-claims-not-proves]")) {
    node.innerHTML = CLAIMS_NOT_PROVES_HTML;
  }
}
