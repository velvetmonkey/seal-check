// SPDX-License-Identifier: Apache-2.0
import { b64urlToStr } from "./receipt.js";

export function pastedReceiptDocumentOrError(raw) {
  const text = raw.trim();
  if (!text) return { ok: false, error: "receipt refused: empty document." };
  // JSON documents (including malformed objects) belong to the validator.
  // Never interpret a URL inside their members as a replacement document.
  if ((text.startsWith("{") || text.startsWith("["))) return { ok: true, document: raw };
  try {
    JSON.parse(text);
    return { ok: true, document: raw };
  } catch { /* A non-JSON input may be a standalone receipt link or blob. */ }
  const link = text.match(/^(?:https?:\/\/[^\s#]+)?#receipt=([A-Za-z0-9_-]+=*)$/);

  try {
    if (link) {
      // Require a real absolute URL when this is not the explicit fragment form.
      if (!text.startsWith("#")) new URL(text);
      return { ok: true, document: b64urlToStr(link[1]) };
    }
    if (/^[A-Za-z0-9_-]{8,}=*$/.test(text)) {
      // A bare receipt blob must begin with a JSON object or array after decoding.
      // Inspect the bytes first so ordinary identifiers never reach b64urlToStr.
      let bytes = "";
      try { bytes = atob(text.replace(/-/g, "+").replace(/_/g, "/")); }
      catch { /* A bare token that is not base64url stays literal text. */ }
      if (/^[\t\n\r ]*[{[]/.test(bytes)) return { ok: true, document: b64urlToStr(text) };
    }
  } catch (error) {
    return { ok: false, error: "could not decode that as base64url: " + error.message };
  }
  return { ok: true, document: text };
}
