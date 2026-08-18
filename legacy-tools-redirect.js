// SPDX-License-Identifier: Apache-2.0

// Every id in the former tools.html is accounted for. Removed workbench ids
// deliberately preserve their missing fragment so index.html shows the
// unknown-anchor notice. The former generated receipt summary is a near-match
// to the receipt-checker summary, so it still lands on an explicit refusal.
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

// Location.hash normally carries the leading '#', which distinguishes no
// fragment ("") from an empty fragment ("#"). Chromium's Location.hash getter
// collapses the latter to "", even though Location.href retains the delimiter.
// Recover only that delimiter; do not trim or classify fragment characters.
export function legacyToolsRequestedHash(location) {
  if (location.hash) return location.hash;
  return location.href.includes("#") ? "#" : "";
}

export function legacyToolsDestination(href) {
  const source = new URL(href);
  const target = new URL("index.html", source);
  target.search = source.search;
  const oldId = source.hash.slice(1);
  const newId = LEGACY_TOOLS_ANCHOR_TARGETS[oldId] ?? oldId;
  target.hash = newId ? `#${newId}` : "";
  return target.href;
}

export function rememberLegacyToolsNavigation(storage, destination, requestedHash) {
  try {
    storage.setItem(LEGACY_TOOLS_NAVIGATION_KEY, JSON.stringify({ destination, requestedHash }));
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

  const requestedHash = navigation?.requestedHash ?? location.hash;
  if (!requestedHash) return "no-fragment";

  const fragment = location.hash.slice(1);
  if (document.getElementById(fragment)) return "found";

  const requestedFragment = navigation?.requestedHash?.slice(1) ?? fragment;
  const namedMessage = document.getElementById("legacy-missing-fragment-named");
  const collapsedMessage = document.getElementById("legacy-missing-fragment-collapsed");
  if (requestedFragment) {
    document.getElementById("legacy-missing-fragment-name").textContent = requestedFragment;
    namedMessage.hidden = false;
    collapsedMessage.hidden = true;
  } else {
    namedMessage.hidden = true;
    collapsedMessage.hidden = false;
  }
  document.getElementById("legacy-missing-fragment").hidden = false;
  return "missing";
}
