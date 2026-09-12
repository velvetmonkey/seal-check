// SPDX-License-Identifier: Apache-2.0
import { b64urlToStr } from "./receipt.js";

export function pastedReceiptDocumentOrError(raw) {
  const text = raw.trim();
  if (!text) return { ok: false, error: "receipt refused: empty document." };
  // Decode only a whole pasted URL (or standalone fragment). A receipt may
  // itself contain links; those strings must remain part of its JSON bytes.
  const link = text.match(/^(?:https?:\/\/[^\s"'<>#]+)?#receipt=([A-Za-z0-9_-]+={0,2})$/);
  try {
    if (link) return { ok: true, document: b64urlToStr(link[1]) };
    if (/^[A-Za-z0-9_-]{8,}=*$/.test(text)) return { ok: true, document: b64urlToStr(text) };
  } catch (error) {
    return { ok: false, error: "could not decode that as base64url: " + error.message };
  }
  return { ok: true, document: text };
}
