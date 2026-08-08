# Proof Reference

This repository does not contain Lean proof source. It carries a deployed or checking artifact that is tied back to the Lean rulebook by pinned hashes and conformance tests.

Canonical proof references are in the two Lean repositories:

- `mcp-seal-dev/docs/PROOF-REFERENCE.md` for the approval automaton rulebook.
- `seal-host/docs/PROOF-REFERENCE.md` for multi-gate non-bypass, append-only and tamper-evident records, capability adequacy, non-interference, and replay isolation.

The relevant verified host locations were checked by grep in `seal-host`:

| Claim | Theorem | Location |
|---|---|---|
| Multi-gate non-bypass | `Host.step_forward_non_bypass` | `Host/Composition.lean:492` |
| Append-only record | `Host.Record.head_after_append` | `Host/Record.lean:57` |
| Tamper-evident record | `Host.Record.tamper_evident` | `Host/Record.lean:67` |
| Netstring encoding injective | `Host.Encoding.encodeParts_injective` | `Host/Encoding.lean:217` |
| Capability clash or equality | `Host.CapabilityAdequacy.capability_sound_or_commitment_clash` | `Host/CapabilityAdequacy.lean:123` |
| Approval authorizes only its target | `Host.CapabilityAdequacy.approval_authorizes_only_its_target'` | `Host/CapabilityAdequacy.lean:148` |
| Single-request non-interference | `Host.NonInterference.observe_noninterference` | `Host/NonInterference.lean:173` |
| Replay isolation | `Host.ReplayIsolation.replay_isolation_trace` | `Host/ReplayIsolation.lean:210` |

Use this repository's tests to check that its local artifact still matches the pinned kernel identity.
