// SPDX-License-Identifier: Apache-2.0
//
// ============================ TEST-ONLY — NOT SHIPPED ========================
// v3 (§12) validator tests: the record_version === 3 branch, the release-
// authority extras, and the Object B Ed25519 signature over the preserve_order
// preimage. Includes the seven physical negative controls from the v3 rollout
// brief — the controls ARE the deliverable, not the happy path.
//
// Fixtures are REAL seal-host artifacts (unmodified):
//   fixtures/host-v3-block.receipt.json  — record_version 3, BLOCK, signed
//   fixtures/host-v2-block.receipt.json  — record_version 2, BLOCK (regression)
// The ALLOW release-authority path has no on-disk host artifact yet; it is
// exercised with a vector minted here that mirrors the producer byte-for-byte
// (rust/src/release.rs attach_and_sign), signed with a fixed test seed.
//
// Run:  node test/receipt-format-v3.test.cjs
// ============================================================================
const fs = require("fs");
const path = require("path");

let failures = 0;
function check(name, got, want) {
  const pass = got === want;
  if (!pass) failures++;
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `\n      got  ${got}\n      want ${want}`}`);
}
const fixture = (f) => JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", f), "utf8"));
const clone = (o) => JSON.parse(JSON.stringify(o));

(async () => {
  const F = await import("file://" + path.resolve(__dirname, "..", "receipt-format.js"));
  const nacl = (await import("file://" + path.resolve(__dirname, "..", "vendor", "nacl.js"))).default;
  // The injected primitive: (message, signature, publicKey) -> boolean.
  const ed = (msg, sig, pk) => nacl.sign.detached.verify(msg, sig, pk);
  const V = (r) => F.validateReceipt(r, { ed25519Verify: ed });

  const utf8 = (s) => new TextEncoder().encode(s);
  const bytesHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const B64S = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const b64enc = (bytes, alphabet, pad) => {
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const chunk = [bytes[i], bytes[i + 1], bytes[i + 2]];
      const n = Math.min(3, bytes.length - i);
      const buf = (chunk[0] << 16) | ((chunk[1] || 0) << 8) | (chunk[2] || 0);
      out += alphabet[(buf >> 18) & 63] + alphabet[(buf >> 12) & 63];
      out += n > 1 ? alphabet[(buf >> 6) & 63] : pad ? "=" : "";
      out += n > 2 ? alphabet[buf & 63] : pad ? (n > 1 ? "=" : "=") : "";
    }
    return out;
  };

  const hostV3 = fixture("host-v3-block.receipt.json");
  const hostV2 = fixture("host-v2-block.receipt.json");

  // ---- CONTROL 1: a real v3 receipt from the host VALIDATES -----------------
  let r = V(hostV3);
  check("C1 real host v3 BLOCK validates", JSON.stringify([r.ok, r.version, r.errors]),
    JSON.stringify([true, "v3", []]));
  check("C1 receipt_signature_valid is true", r.receipt_signature_valid, true);

  // ---- CONTROL 2: a real v2 receipt still VALIDATES (no regression) ---------
  r = V(hostV2);
  check("C2 real host v2 BLOCK still validates", JSON.stringify([r.ok, r.version, r.errors]),
    JSON.stringify([true, "v2", []]));
  check("C2 v2 result carries NO receipt_signature_valid flag (v3-only claim)",
    "receipt_signature_valid" in r, false);

  // ---- CONTROL 3: flip one byte of signature.value → REFUSED ----------------
  let t = clone(hostV3);
  t.signature.value = (t.signature.value[0] === "A" ? "B" : "A") + t.signature.value.slice(1);
  r = V(t);
  check("C3 flipped signature.value refused", r.ok, false);
  check("C3 receipt_signature_valid is false", r.receipt_signature_valid, false);
  check("C3 error names the Ed25519 failure",
    r.errors.some((e) => e.includes("Ed25519 verification failed")), true);

  // ---- CONTROL 4: flip one byte of a COVERED field, signature intact --------
  t = clone(hostV3);
  t.operation_id = (t.operation_id[0] === "0" ? "1" : "0") + t.operation_id.slice(1);
  r = V(t);
  check("C4 flipped covered field (operation_id) refused", r.ok, false);
  check("C4 refusal is cryptographic (preimage no longer matches)",
    r.errors.some((e) => e.includes("Ed25519 verification failed")), true);

  // ---- CONTROL 5: remove signature from a v3 record → REFUSED ---------------
  t = clone(hostV3);
  delete t.signature;
  r = V(t);
  check("C5 signature-less v3 refused (absent means invalid)", r.ok, false);
  check("C5 error says absent-means-invalid",
    r.errors.some((e) => e.includes("absent means invalid")), true);
  check("C5 receipt_signature_valid is false", r.receipt_signature_valid, false);

  // ---- CONTROL 6: reorder two keys before verifying (preserve_order crux) ---
  t = {};
  const keys = Object.keys(hostV3);
  [keys[2], keys[3]] = [keys[3], keys[2]]; // swap tool <-> arguments
  for (const k of keys) t[k] = hostV3[k];
  r = V(t);
  check("C6 reordering two keys BREAKS the signature (insertion order is covered)",
    r.errors.some((e) => e.includes("Ed25519 verification failed")), true);
  check("C6 reordered record refused", r.ok, false);

  // ---- CONTROL 7: unknown record_version: 4 → REFUSED at the discriminator --
  t = clone(hostV3);
  t.record_version = 4;
  r = F.validateReceipt(t);
  check("C7 record_version 4 refused with the discriminator message",
    JSON.stringify([r.ok, r.version, r.errors]),
    JSON.stringify([false, null, ["no recognized version discriminator"]]));

  // ---- fail closed without a primitive --------------------------------------
  r = F.validateReceipt(clone(hostV3)); // no opts.ed25519Verify
  check("v3 without an Ed25519 primitive FAILS (verification cannot be skipped)", r.ok, false);
  check("…with an explicit UNVERIFIED error", r.errors.some((e) => e.includes("UNVERIFIED")), true);
  check("…and receipt_signature_valid false", r.receipt_signature_valid, false);
  check("v2 validation needs no primitive (unchanged single-arg call)",
    F.validateReceipt(hostV2).ok, true);

  // ---- signature envelope shape negatives -----------------------------------
  for (const [field, bad, label] of [
    ["domain", "seal.object-a/v1", "wrong domain"],
    ["algorithm", "Ed448", "wrong algorithm"],
    ["encoding", "base64", "wrong encoding"],
    ["key_id", "0".repeat(64), "key_id != sha256(public_key)"],
  ]) {
    t = clone(hostV3);
    t.signature[field] = bad;
    check(`signature ${label} refused`, V(t).ok, false);
  }
  t = clone(hostV3);
  t.signature.extra = 1;
  check("signature envelope with an extra member refused", V(t).ok, false);

  // ---- v3 field negatives ---------------------------------------------------
  t = clone(hostV3); t.release_status = "DONE";
  check("unknown release_status token refused", V(t).ok, false);
  t = clone(hostV3); t.durability_class = "best_effort";
  check("unknown durability_class token refused", V(t).ok, false);
  t = clone(hostV3); t.release_status = "PENDING";
  check("non-ALLOW carrying PENDING refused", V(t).ok, false);
  t = clone(hostV3); t.release_frame = { encoding: "base64", length: 0, sha256: "0".repeat(64), base64: "" };
  check("non-ALLOW carrying release_frame refused", V(t).ok, false);
  t = clone(hostV3); delete t.release_status;
  check("missing release_status refused", V(t).ok, false);
  t = clone(hostV3); delete t.operation_id;
  check("missing operation_id refused", V(t).ok, false);
  t = clone(hostV3); delete t.durability_class;
  check("missing durability_class refused", V(t).ok, false);

  // ---- v1 `signature` name collision: disjoint discriminators ---------------
  // A v1 receipt with the OPTIONAL live-demo HMAC field named `signature`
  // must classify as v1 (never reach the v3 branch) and stay accepted.
  const v1args = { operation: "insert", table: "t" };
  const v1hmac = {
    seal_receipt: "v1", tool: "db.execute", arguments: v1args,
    canonical_request: F.canonicalRequest("db.execute", v1args),
    canonical_request_sha256: F.canonicalRequestSha256("db.execute", v1args),
    bypass: false, verdict: "BLOCK", reason: "no grant", deny_kernel: "cap",
    certs: [], emitted_bytes: "{}",
    kernel_identity: { wasm_sha256: "0".repeat(64), self_verified: true },
    kernel_config: { epoch: 1 }, granted_capabilities: [],
    signature: { hmac_sha256: "ab".repeat(32) }, // v1 legacy shape, unchecked
  };
  r = F.validateReceipt(v1hmac);
  check("v1 + legacy HMAC signature classifies as v1 and validates",
    JSON.stringify([r.ok, r.version]), JSON.stringify([true, "v1"]));
  check("v1 result carries NO receipt_signature_valid flag",
    "receipt_signature_valid" in r, false);

  // ================= ALLOW release-authority path (minted vector) ============
  // Mirrors rust/src/release.rs: operation_id injected into the frame before
  // the closing brace, sha256 over the FULL frame (terminator included),
  // post_state_hash over {"operation_id":…,"release_frame_sha256":…}.
  const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(7));
  const pubHex = bytesHex(kp.publicKey);
  const opId = "ab".repeat(32);
  const mintAllow = () => {
    const base = clone(hostV2); // real v2 body as the substrate
    const a = {};
    for (const k of Object.keys(base)) a[k] = base[k];
    a.record_version = 3;
    a.verdict = "ALLOW";
    a.reason = "every gating kernel allows";
    a.deny_kernel = null;
    a.authorization = "approval";
    a.approval = {
      approval_identity: { channel: "file" },
      policy_hash: F.canonicalJsonSha256(a.kernel_config),
    };
    a.granted_capabilities = [{ target: "6bff1759cf3c00f781f0b15d428f4cf84e59f8b10be48dd4dd742175a3e6f984" }];
    // Frame: the canonical request line with operation_id injected, + "\n".
    const body = a.canonical_request;
    const frameStr = body.slice(0, -1) + `,"operation_id":${JSON.stringify(opId)}}` + "\n";
    const frame = utf8(frameStr);
    const frameSha = F.sha256Hex(frame);
    a.release_status = "PENDING";
    a.operation_id = opId;
    a.durability_class = "asserted_local_fsync";
    a.release_valid_until = 1754500000000;
    a.post_state_hash = F.postStateHash(opId, frameSha);
    a.release_frame = { encoding: "base64", length: frame.length, sha256: frameSha, base64: b64enc(frame, B64S, true) };
    const sig = nacl.sign.detached(F.receiptSignaturePreimage(a), kp.secretKey);
    a.signature = {
      domain: "seal.object-b/v1", algorithm: "Ed25519",
      public_key: pubHex, key_id: F.sha256Hex(kp.publicKey),
      encoding: "base64url-nopad", value: b64enc(sig, B64U, false),
    };
    return a;
  };

  const allow = mintAllow();
  r = V(allow);
  check("minted v3 ALLOW validates", JSON.stringify([r.ok, r.version, r.errors]),
    JSON.stringify([true, "v3", []]));
  check("minted v3 ALLOW receipt_signature_valid", r.receipt_signature_valid, true);

  t = clone(allow); t.release_status = "NOT_APPLICABLE";
  check("ALLOW with NOT_APPLICABLE refused", V(t).ok, false);
  t = clone(allow); delete t.release_frame;
  check("ALLOW missing release_frame refused", V(t).ok, false);
  t = clone(allow); delete t.release_valid_until;
  check("ALLOW missing release_valid_until refused", V(t).ok, false);
  t = clone(allow); delete t.post_state_hash;
  check("ALLOW missing post_state_hash refused", V(t).ok, false);
  t = clone(allow); t.release_frame.sha256 = t.release_frame.sha256.replace(/^./, (c) => (c === "0" ? "1" : "0"));
  check("release_frame.sha256 mismatch refused", V(t).ok, false);
  t = clone(allow); t.release_frame.length += 1;
  check("release_frame.length mismatch refused", V(t).ok, false);
  t = clone(allow); t.post_state_hash = "0".repeat(64);
  r = V(t);
  check("post_state_hash bind mismatch refused", r.ok, false);
  check("…and named as the operation-state bind",
    r.errors.some((e) => e.includes("bind broken")), true);
  // Frame carrying a DIFFERENT operation_id than the signed top-level field —
  // re-signed so only the bind check (not the signature) can catch it.
  t = clone(allow);
  {
    const otherId = "cd".repeat(32);
    const frameStr = t.canonical_request.slice(0, -1) + `,"operation_id":${JSON.stringify(otherId)}}` + "\n";
    const frame = utf8(frameStr);
    const frameSha = F.sha256Hex(frame);
    t.post_state_hash = F.postStateHash(t.operation_id, frameSha);
    t.release_frame = { encoding: "base64", length: frame.length, sha256: frameSha, base64: b64enc(frame, B64S, true) };
    delete t.signature;
    const sig = nacl.sign.detached(F.receiptSignaturePreimage(t), kp.secretKey);
    t.signature = { domain: "seal.object-b/v1", algorithm: "Ed25519", public_key: pubHex,
      key_id: F.sha256Hex(kp.publicKey), encoding: "base64url-nopad", value: b64enc(sig, B64U, false) };
  }
  r = V(t);
  check("frame operation_id != signed operation_id refused even under a fresh signature",
    r.ok, false);
  check("…named as the forwarded-id bind",
    r.errors.some((e) => e.includes("forwarded unchanged")), true);

  // ---- preimage vector: pin the exact byte layout ---------------------------
  const pre = F.receiptSignaturePreimage({ a: 1, signature: { ignored: true } });
  const preHex = bytesHex(pre);
  // "seal.object-b/v1" + NUL + u64_be(7) + {"a":1}
  check("preimage byte layout (domain||NUL||u64_be(len)||bytes)", preHex,
    bytesHex(utf8("seal.object-b/v1")) + "00" + "0000000000000007" + bytesHex(utf8('{"a":1}')));

  console.log(failures ? `\n${failures} FAILURE(S)` : "\nall v3 checks passed");
  process.exit(failures ? 1 : 0);
})();
