// SPDX-License-Identifier: Apache-2.0
// One transport decoder for links, pasted blobs, uploaded encoded receipts,
// and raw files chosen through the picker. Keep the fragment classifier's
// inclusive encoded-size ceiling on every base64url path.
const MAX_ENCODED_RECEIPT_LENGTH = 128 * 1024;
export const INVALID_UTF8_MESSAGE = "receipt payload is not valid UTF-8";

export function decodeUtf8Bytes(bytes) {
  try {
    // Preserve TextDecoder's existing BOM removal; all other valid text is exact.
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(INVALID_UTF8_MESSAGE);
  }
}

export function b64urlToStr(value) {
  if (value.length > MAX_ENCODED_RECEIPT_LENGTH)
    throw new Error(`receipt payload exceeds ${MAX_ENCODED_RECEIPT_LENGTH} encoded characters (got ${value.length})`);
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(value) || value.length % 4 === 1)
    throw new Error("receipt payload is not valid base64url");
  let encoded = value.replace(/-/g, "+").replace(/_/g, "/");
  while (encoded.length % 4) encoded += "=";
  const bytes = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
  return decodeUtf8Bytes(bytes);
}
