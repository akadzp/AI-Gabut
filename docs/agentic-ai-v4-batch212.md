# Agentic AI V4 — Batch 212

## Scope

Batch 212 adds lifecycle renewal and revocation for multi-checkpoint recovery-intent finalization attestations, a dedicated independent external checkpoint for finalization-attestation lifecycle evidence, and recovery-gate enforcement against stale, revoked, or unanchored lifecycle records.

## New lifecycle events

- `proof_continuity_finalization_attestation_lifecycle_intent`
- `proof_continuity_finalization_attestation_lifecycle_renewed`
- `proof_continuity_finalization_attestation_lifecycle_revoked`
- `proof_continuity_finalization_attestation_lifecycle_superseded`
- `proof_continuity_finalization_attestation_lifecycle_finalized`

Renewal creates a new signed finalization-attestation generation and links it to the predecessor by ID and digest. Revocation is terminal for the targeted attestation generation. Lifecycle operations use bounded, resumable phases; each phase is persisted before the relevant external checkpoints advance.

## Independent checkpoint

Trust domain: `cross_domain_recovery_gate_proof_continuity_finalization_attestation_lifecycles`

The checkpoint snapshot covers finalization-attestation events and lifecycle events. It is independently enrolled and checked for provider/endpoint reuse. The checkpoint is included in cross-domain convergence only when configured, preserving compatibility for deployments that have not enabled it.

### Environment configuration

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_LIFECYCLE_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_LIFECYCLE_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_LIFECYCLE_ANCHOR=true
```

When strict mode is enabled, enrollment must be completed before lifecycle mutation. Credentials and private keys are not included in source archives.

## API routes

Under the recovery-gate proof-continuity API root:

- `GET finalization-attestation-lifecycle-checkpoint/status`
- `GET finalization-attestation-lifecycle-checkpoint/audit`
- `POST finalization-attestation-lifecycle-checkpoint/enrollment/prepare`
- `POST finalization-attestation-lifecycle-checkpoint/enrollment/apply`
- `POST finalization-attestation-lifecycle-checkpoint/reconcile`
- `POST finalization-attestation/lifecycle/prepare`
- `POST finalization-attestation/lifecycle/apply`
- `GET finalization-attestation/lifecycle/audit`

## Recovery and decision-gate behavior

- Retry reuses the same challenge and operation IDs; it does not duplicate lifecycle events.
- Checkpoint advancement is attempted after each persisted phase. A failed external write leaves the operation recoverable and the decision gate blocked.
- Renewal is not current until replacement, supersession, finalization, and required checkpoint advancement are complete.
- Revocation blocks current-decision use even when its lifecycle history is valid and externally anchored.
- Provider reuse, rollback, signing-key cutoff, or stale checkpoint binding blocks current-decision use.

## Validation recorded for Batch 212

- Batch 212 focused regression tests: 5/5 passed when run individually.
- Batch 211 focused compatibility tests: 2/2 passed when run individually.
- Batch 210 multi-checkpoint recovery compatibility test: 1/1 passed.
- Batch 209 convergence compatibility test: 1/1 passed after updating convergence to include the new checkpoint only when configured.
- Full cumulative `npm test` was not claimed as passing.
