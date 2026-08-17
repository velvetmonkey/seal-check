// SPDX-License-Identifier: Apache-2.0
import { b64urlToStr } from "./receipt.js";

export function pastedReceiptDocumentOrError(raw) {
  const text = raw.trim();
  if (!text) return { ok: false, error: "receipt refused: empty document." };
  const link = text.match(/#receipt=([A-Za-z0-9_-]+=*)/);
  try {
    if (link) return { ok: true, document: b64urlToStr(link[1]) };
    if (/^[A-Za-z0-9_-]{8,}=*$/.test(text)) return { ok: true, document: b64urlToStr(text) };
  } catch (error) {
    return { ok: false, error: "could not decode that as base64url: " + error.message };
  }
  return { ok: true, document: text };
}
