// SPDX-License-Identifier: Apache-2.0
// Total classification of the URL fragment used by the receipt checker.
// Only the literal absence of a fragment is allowed to select the bundled
// example. Every other fragment value is visitor-owned and ends in one of the
// five explicit visitor states below.
import { classifyReceiptDocument } from "./receipt-format.js";

// 128 KiB of encoded receipt text is over 12 times the largest checked-in
// receipt fixture (7,605 bytes, about 10 KiB as base64url).
const MAX_ENCODED_RECEIPT_LENGTH = 128 * 1024;

function decodeBase64url(value) {
  if (value.length > MAX_ENCODED_RECEIPT_LENGTH)
    throw new Error(`receipt payload exceeds ${MAX_ENCODED_RECEIPT_LENGTH} encoded characters (got ${value.length})`);
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(value) || value.length % 4 === 1)
    throw new Error("receipt payload is not valid base64url");
  let encoded = value.replace(/-/g, "+").replace(/_/g, "/");
  while (encoded.length % 4) encoded += "=";
  const bytes = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export function classifyReceiptFragment(hash) {
  if (hash === "") return { kind: "absent" };

  const params = new URLSearchParams(hash.startsWith("#") ? hash.slice(1) : hash);
  if (!params.has("receipt")) return {
    kind: "unparseable",
    error: "receipt fragment is not understood — expected #receipt=<base64url receipt>.",
  };

  const encoded = params.get("receipt");
  if (encoded === "") return {
    kind: "empty",
    error: "receipt link is empty — include a base64url receipt after #receipt=.",
  };
  if (encoded.trim() === "") return {
    kind: "whitespace-only",
    error: "receipt link contains only whitespace — include a receipt document after #receipt=.",
    document: encoded,
  };

  let document;
  try {
    document = decodeBase64url(encoded);
  } catch (error) {
    return { kind: "unparseable", error: `could not decode the receipt link: ${error.message}` };
  }

  if (document.trim() === "") return {
    kind: "whitespace-only",
    error: "receipt link contains only whitespace — include a receipt document after #receipt=.",
    document,
  };

  const classified = classifyReceiptDocument(document);
  if (classified.family === "malformed") return {
    kind: "unparseable",
    error: "receipt document refused: " + classified.errors.join("; "),
    document,
    classified,
  };
  if (classified.family !== "decision") return {
    kind: "wrong-shape",
    document,
    classified,
  };
  return { kind: "valid-receipt", document, classified };
}
