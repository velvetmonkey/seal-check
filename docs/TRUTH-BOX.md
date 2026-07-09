# Truth box (canonical)

<!-- Canonical copy of the truth-box claim block: runtime profile, claim,
     non-claim. The README mirrors these three lines verbatim between the same
     markers. The per-repo "Map" line is NOT part of this block (its links are
     relative in the seal umbrella, absolute here). Edit here first;
     scripts/claims-drift.mjs enforces equality. Keep byte-identical to the
     seal umbrella's docs/TRUTH-BOX.md. -->

<!-- truthbox:begin -->
> **Runtime profile: `compatible`.** Strict `canonical-l0` is proved and modelled, not the deployed route yet.
> **Claim:** policy-covered request-effects recognised by the compatible MCP boundary require a matching live human approval and an allowing Lean kernel verdict; seam failures block; every decision emits replayable evidence.
> **Non-claim:** the deployed host is not proved end to end, and canonical parser rejection is not currently the runtime gate. Host `ApprovalRecord` tokens are a separate signed channel from the v2 canonical approval tuple.
<!-- truthbox:end -->
