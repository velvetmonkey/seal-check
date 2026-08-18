// SPDX-License-Identifier: Apache-2.0

// Every id in the former tools.html is accounted for. Result/control ids land
// on the fold that owns them; the former generated receipt summary has no
// equivalent before a call is run, so it lands on an explicit refusal notice.
export const LEGACY_TOOLS_ANCHOR_TARGETS = Object.freeze({
  "kernel-status": "kernel-status", "more-tools": "workbench",
  check: "check", "call-input": "check", "run-btn": "check", "run-error": "check",
  result: "check", verdict: "check", "deny-kernel": "check", reason: "check",
  "witness-wrap": "check", "cert-count": "check", witness: "check",
  "download-receipt": "check", "rerun-receipt": "check", determinism: "check",
  "receipt-summary-heading": "legacy-receipt-summary", "receipt-summary": "legacy-receipt-summary",
  receipt: "check", replay: "replay", "replay-all": "replay", "replay-summary": "replay", corpus: "replay",
  "badge-sec": "badge-sec", "badge-preview": "badge-sec", "copy-badge-svg": "badge-sec",
  "copy-badge-md": "badge-sec", "copy-status": "badge-sec", spec: "spec", "spec-empty": "spec",
  "spec-map": "spec", claims: "claims", "ident-sha": "ident-sha",
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
