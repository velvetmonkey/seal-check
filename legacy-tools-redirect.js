// SPDX-License-Identifier: Apache-2.0

// Every id in the former tools.html is accounted for. Deleted workbench anchors
// preserve a fragment that no longer exists so index.html can show the legacy
// missing-anchor notice instead of silently landing the reader at the page top.
// The former generated receipt summary is a near-match to the receipt checker
// summary, so it lands on an explicit refusal notice rather than that summary.
export const LEGACY_TOOLS_ANCHOR_TARGETS = Object.freeze({
  "kernel-status": "kernel-status", "more-tools": "more-tools",
  check: "check", "call-input": "call-input", "run-btn": "run-btn", "run-error": "run-error",
  result: "result", verdict: "verdict", "deny-kernel": "deny-kernel", reason: "reason",
  "witness-wrap": "witness-wrap", "cert-count": "cert-count", witness: "witness",
  "download-receipt": "download-receipt", "rerun-receipt": "rerun-receipt", determinism: "determinism",
  "receipt-summary-heading": "legacy-receipt-summary", "receipt-summary": "legacy-receipt-summary",
  receipt: "receipt", replay: "replay", "replay-all": "replay-all", "replay-summary": "replay-summary", corpus: "corpus",
  "badge-sec": "badge-sec", "badge-preview": "badge-preview", "copy-badge-svg": "copy-badge-svg",
  "copy-badge-md": "copy-badge-md", "copy-status": "copy-status", spec: "spec", "spec-empty": "spec-empty",
  "spec-map": "spec-map", claims: "claims", "ident-sha": "ident-sha",
});

export const LEGACY_TOOLS_NAVIGATION_KEY = "seal-check:legacy-tools-navigation";

export function legacyToolsDestination(href) {
  const source = new URL(href);
  const target = new URL("index.html", source);
  target.search = source.search;
  const oldId = source.hash.slice(1);
  const newId = LEGACY_TOOLS_ANCHOR_TARGETS[oldId] ?? oldId;
  target.hash = newId ? `#${newId}` : "";
  return target.href;
}

export function rememberLegacyToolsNavigation(storage, destination, requestedFragment) {
  try {
    storage.setItem(LEGACY_TOOLS_NAVIGATION_KEY, JSON.stringify({ destination, requestedFragment }));
  } catch {
    // The same-origin referrer remains a fallback when session storage is unavailable.
  }
}

export function revealMissingLegacyToolsFragment({ document, location, storage }) {
  let navigation;
  try {
    navigation = JSON.parse(storage.getItem(LEGACY_TOOLS_NAVIGATION_KEY));
    storage.removeItem(LEGACY_TOOLS_NAVIGATION_KEY);
  } catch {
    navigation = null;
  }

  let cameFromLegacyTools = navigation?.destination === location.href;
  if (!cameFromLegacyTools) {
    try {
      cameFromLegacyTools = new URL(document.referrer).pathname.endsWith("/tools.html");
    } catch {
      cameFromLegacyTools = false;
    }
  }
  if (!cameFromLegacyTools) return "not-legacy-tools";

  const fragment = location.hash.slice(1);
  if (!fragment) return "no-fragment";
  if (document.getElementById(fragment)) return "found";

  const requestedFragment = navigation?.requestedFragment ?? fragment;
  document.getElementById("legacy-missing-fragment-name").textContent = requestedFragment;
  document.getElementById("legacy-missing-fragment").hidden = false;
  return "missing";
}
