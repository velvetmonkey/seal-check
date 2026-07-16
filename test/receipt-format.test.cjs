// SPDX-License-Identifier: Apache-2.0
//
// ============================ TEST-ONLY — NOT SHIPPED ========================
// Vector test for receipt-format.js against the frozen vectors in
// docs/DECISION-RECEIPT-SCHEMA.md (§2 V1/V4, §3 V2/V2b/V3).
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
    bypass: false, verdict: "ALLOW", authorization: "approval", reason: "every gating kernel allows", deny_kernel: null,
    certs: [], emitted_bytes: "{}",
    kernel_identity: { wasm_sha256: "ff1bfd68d7be51b6a395f94dfc46b2fb27ed11dc5833af6a84675f42f9730546", self_verified: true },
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

  // ========================= §11: receipt schema v2 =========================

  // --- §11.3 derived-hash vectors V5-V7
  check("V5 args_hash (§2 V4 args)",
    F.canonicalJsonSha256({ database: "prod", sql: "drop table users" }),
    "46657b69f15f78859ead6dd0d416cbfc9809922757ba90aa16a56b7d73afafc8");
  check("V6 args_hash (§2 V1 args)",
    F.canonicalJsonSha256(v1args),
    "53ae7fa46f79dd2637b3d5af5a160834b755d0a00a66fec11cb313db8bca753c");
  const PAYCFG = { epoch: 1, safety: { approval: { ttl_seconds: 120 }, tools: [
    { name: "payments.send", mode: "guarded",
      payment: { class: "payment", bind: { amount: "amount", merchant: "to", currency: "currency" } },
      target: [{ literal: "pay" }, { arg: "to" }, { arg: "amount" }] },
  ] } };
  const signedConfig = (config) => ({
    payload: JSON.stringify(config), signature: "a".repeat(128), pubkey: "b".repeat(64),
  });
  check("V7 policy_hash (§11.4 example config)",
    F.canonicalJsonSha256(PAYCFG),
    "436c50ce0860d500c188e7e7c8133eed1e41e626b01174727159f3f664e84407");

  // --- §11.5 assembly: key order, derived hashes computed in the seam
  const payArgs = { amount: 40000, to: "supplier-77", currency: "GBP" };
  const v2fields = {
    tool: "payments.send", arguments: payArgs, now: 1000,
    canonical_request: F.canonicalRequest("payments.send", payArgs),
    canonical_request_sha256: F.canonicalRequestSha256("payments.send", payArgs),
    bypass: false, verdict: "ALLOW", authorization: "approval",
    reason: "every gating kernel allows", deny_kernel: null,
    amount: 40000, merchant: "supplier-77", currency: "GBP",
    approval: {
      approval_identity: { channel: "ed25519", key_id: "ab12cd34" },
      nonce: "f".repeat(64), issued_at: 1751900000000, expiry: 1751900120000,
    },
    certs: [], emitted_bytes: "{}",
    kernel_identity: { wasm_sha256: "0".repeat(64), self_verified: true },
    signed_config: signedConfig(PAYCFG),
    kernel_config: PAYCFG,
    granted_capabilities: [{ tool: "payments.send", to: "supplier-77", amount: 40000 }],
  };
  const v2r = F.assembleReceiptV2(v2fields);
  check("assembleReceiptV2 sets discriminator", v2r.seal_receipt, "v2");
  check("assembleReceiptV2 derives args_hash", v2r.args_hash, F.canonicalJsonSha256(payArgs));
  check("assembleReceiptV2 derives approval.policy_hash", v2r.approval.policy_hash, F.canonicalJsonSha256(PAYCFG));
  check("assembleReceiptV2 approval key order",
    JSON.stringify(Object.keys(v2r.approval)),
    JSON.stringify(["approval_identity", "nonce", "issued_at", "expiry", "policy_hash"]));
  check("assembleReceiptV2 top-level key order",
    JSON.stringify(Object.keys(v2r)),
    JSON.stringify(["seal_receipt", "tool", "arguments", "args_hash", "now", "canonical_request",
      "canonical_request_sha256", "bypass", "verdict", "authorization", "reason", "deny_kernel", "amount",
      "merchant", "currency", "approval", "certs", "emitted_bytes", "kernel_identity",
      "signed_config", "kernel_config", "granted_capabilities"]));

  // --- §11.5 roundtrip obligation: assemble(parse(serialize)) byte-identical
  const ser = JSON.stringify(v2r);
  const round = F.assembleReceiptV2(JSON.parse(ser));
  check("v2 roundtrip byte-identical", JSON.stringify(round), ser);

  // --- §11 validation: well-formed v2 passes
  r = F.validateReceipt(v2r);
  check("validateReceipt v2 well-formed", JSON.stringify([r.ok, r.version, r.errors]), JSON.stringify([true, "v2", []]));
  r = F.validateReceipt({ ...v2r, authority_trusted: true });
  check("v2 rejects receipt-supplied authority_trusted", r.ok, false);
  const missingSignedConfig = { ...v2r }; delete missingSignedConfig.signed_config;
  r = F.validateReceipt(missingSignedConfig);
  check("v2 rejects mediated receipt without signed_config", r.ok, false);
  r = F.validateReceipt({ ...v2r, signed_config: { ...v2r.signed_config, extra: true } });
  check("v2 rejects extra signed_config fields", r.ok, false);

  // --- §11.6 recompute-and-reject
  r = F.validateReceipt({ ...v2r, args_hash: F.canonicalJsonSha256({ different: 1 }) });
  check("v2 rejects args_hash mismatch", r.ok, false);
  r = F.validateReceipt({ ...v2r, approval: { ...v2r.approval, policy_hash: "0".repeat(64) } });
  check("v2 rejects policy_hash mismatch", r.ok, false);

  // --- §11.4 payment gates
  r = F.validateReceipt({ ...v2r, amount: 39999 });
  check("v2 rejects amount != bound argument (gate:amount-merchant-mismatch)", r.ok, false);
  r = F.validateReceipt({ ...v2r, merchant: "someone-else" });
  check("v2 rejects merchant != bound argument", r.ok, false);
  const noPay = { ...v2r };
  delete noPay.amount;
  r = F.validateReceipt(noPay);
  check("v2 rejects missing payment field on payment-class tool", r.ok, false);
  const dbArgs = { database: "prod", sql: "select 1" };
  const dbCfg = { epoch: 1, safety: { tools: [{ name: "db.execute", target: [{ arg: "database" }] }] } };
  const fab = F.assembleReceiptV2({
    tool: "db.execute", arguments: dbArgs, bypass: false, verdict: "ALLOW", reason: "ok",
    deny_kernel: null, amount: 1, merchant: "x", currency: "GBP",
    approval: { approval_identity: { channel: "file" } },
    canonical_request_sha256: F.canonicalRequestSha256("db.execute", dbArgs),
    certs: [], emitted_bytes: "{}",
    kernel_identity: { wasm_sha256: "0".repeat(64), self_verified: true },
    signed_config: signedConfig(dbCfg),
    kernel_config: dbCfg, granted_capabilities: [],
  });
  r = F.validateReceipt(fab);
  check("v2 rejects fabricated payment fields on non-payment tool", r.ok, false);

  // --- §11.2 approval identity + channel requiredness
  r = F.validateReceipt({ ...v2r, approval: { ...v2r.approval, approval_identity: { channel: "file", key_id: "x" } } });
  check("v2 rejects key_id off the ed25519 channel", r.ok, false);
  const edMissing = { ...v2r.approval, approval_identity: { channel: "ed25519", key_id: "ab12cd34" } };
  delete edMissing.nonce;
  r = F.validateReceipt({ ...v2r, approval: edMissing });
  check("v2 rejects ed25519 approval without nonce", r.ok, false);
  const allowNoApproval = { ...v2r };
  delete allowNoApproval.approval;
  r = F.validateReceipt(allowNoApproval);
  check("v2 rejects mediated ALLOW without approval block", r.ok, false);
  const explicitAllow = { ...allowNoApproval, authorization: "explicit_policy_allow", granted_capabilities: [] };
  r = F.validateReceipt(explicitAllow);
  check("v2 accepts explicit policy ALLOW without approval", r.ok, true);
  r = F.validateReceipt({ ...explicitAllow, approval: { approval_identity: { channel: "interactive" } } });
  check("v2 rejects approval block on explicit policy ALLOW", r.ok, false);

  // --- host_identity (Gate 0A receipt parity): native-exe + Lean-FFI hashes 64-hex,
  // equivalence pinned to "not_proven" so the host never overclaims Rust == Lean.
  const hostOk = { ...v2r, host_identity: {
    native_executable_sha256: "a".repeat(64), lean_ffi_sha256: "b".repeat(64), equivalence: "not_proven" } };
  r = F.validateReceipt(hostOk);
  check("v2 accepts well-formed host_identity", r.ok, true);
  r = F.validateReceipt({ ...v2r, host_identity: {
    native_executable_sha256: "nothex", lean_ffi_sha256: "b".repeat(64), equivalence: "not_proven" } });
  check("v2 rejects host_identity non-hex hash", r.ok, false);
  r = F.validateReceipt({ ...hostOk, host_identity: { ...hostOk.host_identity, equivalence: "proven" } });
  check("v2 rejects host_identity equivalence != not_proven", r.ok, false);
  r = F.validateReceipt({ ...v2r, host_identity: "not-an-object" });
  check("v2 rejects non-object host_identity", r.ok, false);
  const fileOk = F.assembleReceiptV2({
    ...v2fields,
    tool: "store.update", arguments: { op: "orset.add", key: "k1" },
    canonical_request: undefined,
    canonical_request_sha256: F.canonicalRequestSha256("store.update", { op: "orset.add", key: "k1" }),
    amount: undefined, merchant: undefined, currency: undefined,
    approval: { approval_identity: { channel: "interactive" } },
    kernel_config: { epoch: 1, safety: { tools: [{ name: "store.update", target: [{ literal: "store" }] }] } },
    signed_config: signedConfig({ epoch: 1, safety: { tools: [{ name: "store.update", target: [{ literal: "store" }] }] } }),
    granted_capabilities: [{ target: "6bff1759cf3c00f781f0b15d428f4cf84e59f8b10be48dd4dd742175a3e6f984" }],
  });
  r = F.validateReceipt(fileOk);
  check("v2 interactive-channel approval without nonce/expiry accepted (honesty rule)",
    JSON.stringify([r.ok, r.errors]), JSON.stringify([true, []]));

  // --- v1 stays accepted-legacy under the v2-aware validator
  r = F.validateReceipt(v1ok);
  check("v1 still validates (accepted-legacy)", JSON.stringify([r.ok, r.version]), JSON.stringify([true, "v1"]));

  // --- §11.1/§11.5 unparseable-request rule: assembly ------------------------
  // seal-host (main @ 3a74dbf) emits request_sha256 on every native receipt and
  // request_parse_error when serde could not re-parse the wire line the kernel
  // judged; on those lines the structured request fields are absent and
  // request_sha256 is the ONLY request identity. The assembler must not drop it.
  const unpAsm = F.assembleReceiptV2({
    now: 1000,
    request_sha256: "c".repeat(64),
    request_parse_error: "cannot parse mediated request for receipt: number out of range at line 1 column 145",
    bypass: false, verdict: "BLOCK", reason: "safety kernel: cert", deny_kernel: "safety",
    certs: [], emitted_bytes: "{}",
    kernel_identity: { wasm_sha256: "0".repeat(64), self_verified: true },
    signed_config: signedConfig(PAYCFG), kernel_config: PAYCFG, granted_capabilities: [],
  });
  check("assembleReceiptV2 preserves request_sha256 + request_parse_error (§11.5)",
    JSON.stringify(Object.keys(unpAsm)),
    JSON.stringify(["seal_receipt", "now", "request_sha256", "request_parse_error", "bypass",
      "verdict", "reason", "deny_kernel", "certs", "emitted_bytes", "kernel_identity",
      "signed_config", "kernel_config", "granted_capabilities"]));
  check("unparseable-request roundtrip byte-identical",
    JSON.stringify(F.assembleReceiptV2(JSON.parse(JSON.stringify(unpAsm)))), JSON.stringify(unpAsm));
  const withBoth = F.assembleReceiptV2({ ...v2fields, request_sha256: "c".repeat(64) });
  check("request_sha256 sits between canonical_request_sha256 and bypass (§11.5 order)",
    JSON.stringify(Object.keys(withBoth).slice(
      Object.keys(withBoth).indexOf("canonical_request_sha256"),
      Object.keys(withBoth).indexOf("bypass") + 1)),
    JSON.stringify(["canonical_request_sha256", "request_sha256", "bypass"]));

  // --- §11.1/§11.2 unparseable-request rule: validation ----------------------
  // "iff parsed": a receipt naming request_parse_error is well-formed exactly
  // when the structured request fields are ABSENT — rejecting it would restore
  // to the verifier the veto the producer was deliberately stripped of, and a
  // producer naming a parse error while supplying structured fields is
  // fabricating.
  r = F.validateReceipt(unpAsm);
  check("unparseable-request receipt validates clean (§11.2)",
    JSON.stringify([r.ok, r.version, r.errors]), JSON.stringify([true, "v2", []]));
  for (const [k, vv] of [["tool", "payments.send"], ["arguments", {}],
    ["args_hash", "0".repeat(64)], ["canonical_request", "{}"],
    ["canonical_request_sha256", "0".repeat(64)]]) {
    r = F.validateReceipt({ ...unpAsm, [k]: vv });
    check(`unparseable + ${k} rejected (fabrication)`, r.ok, false);
  }
  r = F.validateReceipt({ ...unpAsm, request_sha256: "nothex" });
  check("unparseable non-hex request_sha256 rejected", r.ok, false);
  const noRaw = { ...unpAsm }; delete noRaw.request_sha256;
  r = F.validateReceipt(noRaw);
  check("unparseable without request_sha256 rejected", r.ok, false);
  r = F.validateReceipt({ ...unpAsm, request_parse_error: "" });
  check("empty request_parse_error rejected", r.ok, false);
  r = F.validateReceipt({ ...unpAsm, bypass: true });
  check("bypass + request_parse_error rejected (mediated receipts only)",
    r.errors.some((e) => e.includes("only a mediated receipt")), true);
  r = F.validateReceipt({ ...v2r, request_sha256: "c".repeat(64) });
  check("normal mediated receipt may carry request_sha256",
    JSON.stringify([r.ok, r.errors]), JSON.stringify([true, []]));
  r = F.validateReceipt({ ...v2r, request_sha256: "nothex" });
  check("normal receipt non-hex request_sha256 rejected", r.ok, false);

  console.log(failures === 0 ? "\nALL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR", e); process.exit(1); });
