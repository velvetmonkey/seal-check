// SPDX-License-Identifier: Apache-2.0
// Named bypass / parser-differential / stale-capability traces that the live
// kernel must deterministically BLOCK. Data only — no kernel logic. Configs are
// reused from the public seal-config.js scenario set; nothing private here.
//
// Each entry runs against the compiled black-box kernel via kernel.js. The actual
// deny_kernel is read back from the verdict at runtime, so the displayed result is
// always the kernel's, not a hardcoded claim.
import { SCENARIOS, CFG_TEMPORAL, stableHash } from "./seal-config.js";

const S = (k) => SCENARIOS[k];

export const CORPUS = [
  {
    id: "destructive-sql",
    name: "Destructive SQL, unapproved",
    lens: "safety",
    attack: "A tool call tries to run `drop table users` with no human approval on record.",
    why: "The safety kernel guards db.execute on destructive SQL. With no matching approval, the call is blocked.",
    run: "single",
    config: S("destructive-sql").config,
    tool: "db.execute",
    args: S("destructive-sql").args,
    approvals: [],
  },
  {
    id: "self-approve",
    name: "Self-approval of own call",
    lens: "safety (deny-rule)",
    attack: "The caller invokes `approve` to rubber-stamp their own high-stakes action.",
    why: "`approve` is a deny-listed action in this policy; the kernel refuses self-approval outright.",
    run: "single",
    config: S("self-approve").config,
    tool: "approve",
    args: S("self-approve").args,
    approvals: [],
  },
  {
    id: "pay-quorum-missing",
    name: "£40k payment without quorum",
    lens: "consensus",
    attack: "A £40,000 payment carries one approval, but the required 2-of-3 quorum has not voted.",
    why: "The consensus kernel requires a 2-of-3 quorum for high-stakes payments. A single approval is insufficient, so it blocks.",
    run: "single",
    config: S("pay-after").config,
    tool: "payments.send",
    args: S("pay-after").args,
    approvals: S("pay-after").approvals,
  },
  {
    id: "store-subtle",
    name: "Non-convergent store write",
    lens: "convergence",
    attack: "A store.update uses a raw `assign` op instead of a convergent CRDT op.",
    why: "The convergence kernel admits only convergent operations. A blind assign can silently diverge, so it is blocked.",
    run: "single",
    config: S("store-subtle").config,
    tool: "store.update",
    args: S("store-subtle").args,
    approvals: S("store-subtle").approvals,
  },
  {
    id: "temporal-stale-cap",
    name: "Stale capability after revoke",
    lens: "temporal (stateful)",
    attack: "A session is revoked, then the SAME session is replayed to run a destructive db.execute.",
    why: "A temporal policy forbids db.execute after session.revoke. Replaying the revoked capability is blocked even though each call looks individually fine — this needs the stateful kernel that sees the whole ordered trace.",
    run: "seq",
    config: CFG_TEMPORAL,
    tool: "db.execute",
    // Approval target = stableHash([toolName, ...resolved target parts]). Both steps
    // are approved so SAFETY passes — leaving the TEMPORAL kernel as the denier of the
    // post-revoke db.execute (the point of the trace).
    steps: [
      { tool: "session.revoke", args: {}, approvals: [stableHash(["session.revoke", "revoke"])] },
      {
        tool: "db.execute",
        args: { database: "prod", sql: "drop table users" },
        approvals: [stableHash(["db.execute", "db", "prod", "write", "drop table users"])],
      },
    ],
  },
];
