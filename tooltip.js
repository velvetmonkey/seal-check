// SPDX-License-Identifier: Apache-2.0
// Shared tooltip pattern for seal-check: a focusable <button> trigger plus a
// plain-text body, connected by aria-describedby. Presentation only — this
// module holds no verification logic and reads no receipt fields itself; it
// only displays strings its caller already computed.
//
// Pattern (kept in one place so every ⓘ on the page behaves identically):
//   <span class="tip">
//     <button type="button" class="tip-btn" aria-label="About {label}"
//             aria-describedby="tip-N">i</button>
//     <span role="tooltip" id="tip-N" class="tip-body" hidden>{text}</span>
//   </span>
//
// Show: pointer hover over the trigger, or focus on the trigger.
// Hide: pointer/focus leaving both the trigger AND the body (the body is
//   itself hoverable, WCAG 1.4.13), Escape from anywhere, or a click outside
//   any tip. Click/Enter/Space on the trigger toggles a "pinned" state for
//   touch users who cannot hover; a second activation un-pins and hides.
// Never hidden by a timer.

let counter = 0;

// Some callers (receipt-summary.js, exercised under test by a minimal fake
// DOM with no setAttribute) build tooltips outside a real browser document.
// Feature-detect rather than assume: real elements get real attributes
// (required for aria-describedby to actually resolve for a screen reader);
// a fake node without setAttribute gets a plain property instead, which is
// enough for the tests that construct one to inspect textContent/children.
function setAttr(node, name, value) {
  if (typeof node.setAttribute === "function") node.setAttribute(name, value);
  else node[name] = value;
}

// `doc` must be passed explicitly by the caller (container.ownerDocument in
// the browser, or a caller-supplied document-like object under test) — this
// module never assumes a global `document` exists.
export function createTooltip(doc, label, text, { side = "right", id } = {}) {
  const tipId = id || `tip-auto-${++counter}`;
  const wrap = doc.createElement("span");
  wrap.className = "tip";
  const btn = doc.createElement("button");
  btn.type = "button";
  btn.className = "tip-btn";
  setAttr(btn, "aria-label", `About ${label}`);
  setAttr(btn, "aria-describedby", tipId);
  btn.textContent = "i";
  const body = doc.createElement("span");
  setAttr(body, "role", "tooltip");
  body.id = tipId;
  body.className = "tip-body" + (side === "left" ? " left" : "");
  body.hidden = true;
  body.textContent = text;
  wrap.append(btn, body);
  return wrap;
}

const OPEN = new Set();

function tipOf(node) {
  return node && node.closest ? node.closest(".tip") : null;
}
function bodyOf(tip) {
  return tip ? tip.querySelector(".tip-body") : null;
}
function show(tip) {
  const body = bodyOf(tip);
  if (!body) return;
  body.hidden = false;
  OPEN.add(tip);
}
function hide(tip) {
  if (!tip || tip.classList.contains("tip-pinned")) return;
  const body = bodyOf(tip);
  if (body) body.hidden = true;
  OPEN.delete(tip);
}
function hideAll() {
  for (const tip of [...OPEN]) {
    tip.classList.remove("tip-pinned");
    const body = bodyOf(tip);
    if (body) body.hidden = true;
  }
  OPEN.clear();
}

function movedWithinSameTip(tip, relatedTarget) {
  return !!(relatedTarget && tip.contains(relatedTarget));
}

export function installTooltipBehavior(root = document) {
  if (root.__sealTooltipsInstalled) return;
  root.__sealTooltipsInstalled = true;

  root.addEventListener("mouseover", (e) => {
    const tip = tipOf(e.target);
    if (tip) show(tip);
  });
  root.addEventListener("mouseout", (e) => {
    const tip = tipOf(e.target);
    if (!tip || movedWithinSameTip(tip, e.relatedTarget)) return;
    hide(tip);
  });
  root.addEventListener(
    "focusin",
    (e) => {
      const tip = tipOf(e.target);
      if (tip && e.target.classList && e.target.classList.contains("tip-btn")) show(tip);
    },
    true,
  );
  root.addEventListener(
    "focusout",
    (e) => {
      const tip = tipOf(e.target);
      if (!tip || movedWithinSameTip(tip, e.relatedTarget)) return;
      hide(tip);
    },
    true,
  );
  root.addEventListener("click", (e) => {
    const btn = e.target.closest && e.target.closest(".tip-btn");
    const tip = tipOf(e.target);
    if (btn && tip) {
      const pinned = tip.classList.toggle("tip-pinned");
      if (pinned) show(tip);
      else hide(tip);
      return;
    }
    if (!tip) hideAll();
  });
  root.addEventListener("keydown", (e) => {
    if (e.key === "Escape") hideAll();
  });
}
