// SPDX-License-Identifier: Apache-2.0
// Minimal theme switcher. Same mechanism as the seal family docs site: a
// `data-theme` attribute on <html> set to "light" or "dark" (not
// prefers-color-scheme alone, not a class). Loaded as a plain classic
// <script src> (CSP here is `script-src 'self' ...` with no 'unsafe-inline',
// so this cannot be an inline script) and placed early in <head>, before the
// stylesheet, so the attribute is set before first paint and there is no
// flash of the wrong theme.
(function () {
  "use strict";
  var STORAGE_KEY = "seal-check-theme";

  function storedTheme() {
    try {
      var v = window.localStorage.getItem(STORAGE_KEY);
      return v === "light" || v === "dark" ? v : null;
    } catch (e) {
      return null; // storage may be unavailable (privacy mode, file://, etc.)
    }
  }

  function preferredTheme() {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark" : "light";
  }

  var theme = storedTheme() || preferredTheme();
  document.documentElement.setAttribute("data-theme", theme);

  function paint(button, current) {
    // The button always names the mode it switches TO, in visible text —
    // never an icon alone — and aria-pressed reflects whether dark mode is
    // the current state.
    button.textContent = current === "dark" ? "☀ Light mode" : "\u{1F319} Dark mode";
    button.setAttribute("aria-pressed", current === "dark" ? "true" : "false");
  }

  function wire() {
    var button = document.getElementById("theme-toggle");
    if (!button) return;
    paint(button, document.documentElement.getAttribute("data-theme"));
    button.addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { window.localStorage.setItem(STORAGE_KEY, next); } catch (e) { /* best effort */ }
      paint(button, next);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
