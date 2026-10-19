# Agentic AI V4 — Batch 213

## Scope

Batch 213 adds a signed lifecycle receipt for each finalized finalization-attestation lifecycle operation, an independent external checkpoint for those receipts, receipt-chain validation, and decision-gate enforcement against missing, stale, duplicated, or unanchored lifecycle receipts.

## Lifecycle receipt event

- `proof_continuity_finalization_attestation_lifecycle_receipt_finalized`

Each receipt binds the finalized lifecycle event and digest, action event and digest, target attestation, replacement attestation when renewing, lifecycle generation, signing-key lifecycle binding, and predecessor receipt ID/digest. Receipt generations are monotonic. Each finalization has exactly one receipt; replay reuses the original receipt rather than appending a duplicate.

The lifecycle workflow separates finalization and receipt persistence into distinct resumable phases. This lets the normal checkpoint advancement anchor the finalization event before the receipt is appended, avoiding multi-event gaps. If receipt checkpoint advancement fails, the receipt remains persisted and the next apply/reconcile attempt resumes without duplicating it.

## Independent checkpoint

Trust domain: `cross_domain_recovery_gate_finalization_attestation_lifecycle_receipts`

The checkpoint source projection covers the base finalization attestations, lifecycle events, and lifecycle receipt events. Enrollment, status, audit, and reconciliation are independent from the existing finalization-attestation lifecycle checkpoint. Provider/endpoint reuse is rejected.

### Environment configuration

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ANCHOR=true
```

When configured, the receipt checkpoint must be enrolled and current before new lifecycle operations are prepared. Credentials and private keys are not included in source archives.

## API routes

Under the recovery-gate proof-continuity API root:

- `GET finalization-attestation-lifecycle-receipt-checkpoint/status`
- `GET finalization-attestation-lifecycle-receipt-checkpoint/audit`
- `POST finalization-attestation-lifecycle-receipt-checkpoint/enrollment/prepare`
- `POST finalization-attestation-lifecycle-receipt-checkpoint/enrollment/apply`
- `POST finalization-attestation-lifecycle-receipt-checkpoint/reconcile`

## Recovery and decision-gate behavior

- Renewal and revocation each receive a signed receipt after their lifecycle finalization event is persisted.
- Receipt chains bind predecessor ID/digest and reject generation gaps, duplicate finalization bindings, and stale key lifecycle bindings.
- The new checkpoint is advanced with proof-continuity, lifecycle drift-evidence, and finalization-attestation lifecycle checkpoints.
- A failed external receipt checkpoint write leaves the receipt recoverable; retry does not duplicate it.
- Revocation remains terminal. A valid, externally anchored revocation receipt records history but does not make the revoked attestation usable.
- When the checkpoint is configured, convergence and lifecycle preparation reject stale, unanchored, or unhealthy receipt evidence.

## Validation recorded for Batch 213

- Batch 213 focused tests: 5/5 passed individually after ZIP extraction.
- Batch 212 renewal, revocation, and checkpoint-write recovery compatibility tests: 3/3 passed individually after ZIP extraction.
- The renewal receipt, revocation receipt, checkpoint write-failure recovery, strict enrollment/provider-independence, and route/validation checks are covered.
- Full cumulative `npm test` is not claimed as passing.
