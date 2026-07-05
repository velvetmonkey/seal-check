// SPDX-License-Identifier: Apache-2.0
//
// ============================ TEST-ONLY — NOT SHIPPED ========================
// Vector test for receipt-format.js against the frozen vectors in
// seal-host/docs/DECISION-RECEIPT-SCHEMA.md (§2 V1/V4, §3 V2/V2b/V3).
// Fails if the shared module and the normative spec ever disagree.
// Self-contained: all vectors are embedded (no sibling-repo reads).
//
// Run:  node test/receipt-format.test.cjs
// ============================================================================
const path = require("path");

let failures = 0;
function check(name, got, want) {
  const pass = got === want;
  if (!pass) failures++;
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `\n      got  ${got}\n      want ${want}`}`);
}

(async () => {
  const F = await import("file://" + path.resolve(__dirname, "..", "receipt-format.js"));

  // --- sanity: pure-JS sha256 against the NIST empty-string digest
  check("sha256Hex(\"\")",
    F.sha256Hex(new Uint8Array(0)),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  // --- §2 V1: real seal-live-demo receipt (evidence/receipts.jsonl line 1)
  const v1args = { operation: "insert", table: "staging_deploy_audit",
    payload: "{\"deploy_ref\":\"deploy-2026-06-30\"}" };
  check("V1 canonical line (byte-identical to the deployed gateway's stored canonical_request)",
    F.canonicalRequest("db.execute", v1args),
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"operation\":\"insert\",\"table\":\"staging_deploy_audit\",\"payload\":\"{\\\"deploy_ref\\\":\\\"deploy-2026-06-30\\\"}\"}}}");
  check("V1 canonical_request_sha256",
    F.canonicalRequestSha256("db.execute", v1args),
    "66330ea2242d45a5a6b32d85007464125608fec7e88430fa3c23d5c5303db756");

  // --- §2 V4: the convergence proof — Schema K's stored hash (kit block
  // fixture) is exactly what the v1 function produces for K's own (tool, args).
  check("V4 canonical_request_sha256 (Schema K fixture pre-image)",
    F.canonicalRequestSha256("db.execute", { database: "prod", sql: "drop table users" }),
    "460d746ba064ab9398885158dddfd6d32f1722b0efe0d3b6085c8441e9127793");

  // --- §3: capability-target convention [tool, ...policy parts]
  check("V2 store.update literal grant", F.capabilityTarget("store.update", ["store"]), "6bff1759cf3c00f781f0b15d428f4cf84e59f8b10be48dd4dd742175a3e6f984");
  check("V2b payments.send literal grant", F.capabilityTarget("payments.send", ["pay"]), "e35dd14f3e1d02fec3b03a781b7f8928bfd1ce7b7f93a23a7b61228c536bd73a");
  check("V3 live-demo arg-selected grant",
    F.capabilityTarget("db.execute", ["staging_deploy_audit", "insert"]), "351f47a44bcf935c7242432e24bd11db1536d7c1da873f0ca953c8b80ae02433");
  check("capabilityTarget == stableHashParts([tool, ...parts])",
    F.capabilityTarget("db.execute", ["a", "b"]),
    F.stableHashParts(["db.execute", "a", "b"]));

  // --- §1: shape validation
  const v1ok = {
    seal_receipt: "v1", tool: "db.execute", arguments: v1args,
    canonical_request: F.canonicalRequest("db.execute", v1args),
    canonical_request_sha256: F.canonicalRequestSha256("db.execute", v1args),
    bypass: false, verdict: "ALLOW", reason: "every gating kernel allows", deny_kernel: null,
    certs: [], emitted_bytes: "{}",
    kernel_identity: { wasm_sha256: "ebd17c14668176612c49f6e2940b23df82a2c1a7cdef6759f0d6276ae997e9d0", self_verified: true },
    kernel_config: { epoch: 1 },
    granted_capabilities: [{ tool: "db.execute", table: "staging_deploy_audit", operation: "insert" }],
  };
  let r = F.validateReceipt(v1ok);
  check("validateReceipt v1 well-formed", JSON.stringify([r.ok, r.version, r.errors]), JSON.stringify([true, "v1", []]));

  r = F.validateReceipt({ ...v1ok, seal_receipt: undefined, seal_live_receipt: "v0" });
  check("validateReceipt accepts v0-live", JSON.stringify([r.ok, r.version]), JSON.stringify([true, "v0-live"]));

  r = F.validateReceipt({ seal_check_receipt: "v0", input: {}, witness: {} });
  check("validateReceipt rejects legacy Schema K", JSON.stringify([r.ok, r.version]), JSON.stringify([false, "v0-check"]));

  r = F.validateReceipt({ ...v1ok, canonical_request: "{\"tampered\":1}" });
  check("validateReceipt catches stored-line/derived-line mismatch", r.ok, false);

  const byp = { seal_receipt: "v1", tool: "db.execute", arguments: v1args,
    canonical_request_sha256: v1ok.canonical_request_sha256, bypass: true,
    verdict: "ALLOW", reason: "bypass", kernel_identity: { wasm_sha256: null, self_verified: false } };
  r = F.validateReceipt(byp);
  check("validateReceipt bypass receipt (null wasm_sha256 required)", JSON.stringify([r.ok, r.errors]), JSON.stringify([true, []]));

  r = F.validateReceipt({ ...byp, kernel_identity: { wasm_sha256: v1ok.kernel_identity.wasm_sha256, self_verified: true } });
  check("validateReceipt rejects bypass with non-null wasm_sha256", r.ok, false);

  // --- §4 hard split (Day-2 ruling: merged identity INVALID in v1, v0-live grandfathered)
  r = F.validateReceipt({ ...v1ok, kernel_identity: { ...v1ok.kernel_identity, lean_toolchain: "leanprover/lean4:v4.28.0", axioms: [] } });
  check("hard split: v1 rejects toolchain/axioms inside kernel_identity", r.ok, false);
  r = F.validateReceipt({ ...v1ok, seal_receipt: undefined, seal_live_receipt: "v0",
    kernel_identity: { ...v1ok.kernel_identity, lean_toolchain: "leanprover/lean4:v4.28.0", axioms: [] } });
  check("hard split: v0-live merged identity grandfathered", r.ok, true);
  r = F.validateReceipt({ ...v1ok, asserted_provenance: { verified_in_browser: true } });
  check("asserted_provenance.verified_in_browser === true rejected", r.ok, false);

  // --- §3 opaque grant entries + policy recompute
  r = F.validateReceipt({ ...v1ok, granted_capabilities: [{ target: "6bff1759cf3c00f781f0b15d428f4cf84e59f8b10be48dd4dd742175a3e6f984" }] });
  check("opaque {target} grant entry accepted", JSON.stringify([r.ok, r.errors]), JSON.stringify([true, []]));

  const CFG = { safety: { tools: [
    { name: "store.update", target: [{ literal: "store" }] },
    { name: "db.execute", target: [{ arg: "table" }, { arg: "operation" }] },
  ] } };
  let g = F.capabilityTargetsFromPolicy(CFG, [{ tool: "store.update" }]);
  check("recompute literal-target grant (V2)", g.approvals[0], "6bff1759cf3c00f781f0b15d428f4cf84e59f8b10be48dd4dd742175a3e6f984");
  g = F.capabilityTargetsFromPolicy(CFG, [{ tool: "db.execute", table: "staging_deploy_audit", operation: "insert" }]);
  check("recompute arg-target grant (V3)", g.approvals[0], "351f47a44bcf935c7242432e24bd11db1536d7c1da873f0ca953c8b80ae02433");
  g = F.capabilityTargetsFromPolicy(CFG, [{ target: "0".repeat(64) }]);
  check("opaque grant used verbatim + counted", JSON.stringify([g.approvals[0], g.opaque]), JSON.stringify(["0".repeat(64), 1]));
  g = F.capabilityTargetsFromPolicy(CFG, [{ tool: "db.execute", table: "x" }]);
  check("missing arg field reported", g.errors.length > 0, true);

  // --- §1 canonical assembly key order (byte-stability seam)
  const asm = F.assembleReceiptV1({ verdict: "ALLOW", tool: "t", arguments: {}, bypass: false,
    canonical_request_sha256: "0".repeat(64), reason: "r", deny_kernel: null, certs: [],
    emitted_bytes: "e", kernel_identity: { wasm_sha256: "0".repeat(64), self_verified: true },
    kernel_config: {}, granted_capabilities: [] });
  check("assembleReceiptV1 fixed key order",
    JSON.stringify(Object.keys(asm)),
    JSON.stringify(["seal_receipt", "tool", "arguments", "canonical_request_sha256", "bypass",
      "verdict", "reason", "deny_kernel", "certs", "emitted_bytes", "kernel_identity",
      "kernel_config", "granted_capabilities"]));

  console.log(failures === 0 ? "\nALL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
