// SPDX-License-Identifier: Apache-2.0
import { b64urlToStr } from "./receipt.js";

function startsLikeJsonBase64url(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let bits = 0;
  let value = 0;
  for (const character of text) {
    if (character === "=") break;
    const digit = alphabet.indexOf(character);
    if (digit < 0) return false;
    value = (value << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      const byte = (value >> bits) & 255;
      if (byte === 9 || byte === 10 || byte === 13 || byte === 32) continue;
      return byte === 123 || byte === 91;
    }
  }
  return false;
}

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
      // Inspect only the leading bytes without allocating the decoded blob;
      // the shared size guard then runs before atob on receipt-shaped input.
      if (startsLikeJsonBase64url(text)) return { ok: true, document: b64urlToStr(text) };
    }
  } catch (error) {
    return { ok: false, error: "could not decode that as base64url: " + error.message };
  }
  return { ok: true, document: text };
}
