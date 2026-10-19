# Agentic AI V4 — Batch 184

## Attestation-lifecycle external recovery receipts

Batch 184 adds an append-only recovery-receipt ledger for attestation renewal and revocation events. Each receipt binds the exact lifecycle event and digest, target receipt identity/digest, reconciliation receipt identity/digest, and signing-key lifecycle binding. When an Ed25519 signer is configured, the receipt is signed; if finalization attestation is required, a missing signer or invalid signature fails closed.

The ledger is protected by its own external snapshot checkpoint domain, separate from the existing finalization and reconciliation checkpoint providers. Enrollment is explicit. The checkpoint domain must use an independent provider endpoint; reusing a provider object or URL is rejected. A local-only receipt ledger is never reported as externally anchored or usable for a current decision.

## Freshness, crash recovery, and repair

Lifecycle mutation challenges bind the current recovery-receipt checkpoint state when that domain is configured. If the checkpoint is missing, stale, unproven, or affected by policy drift, a new lifecycle mutation is blocked. A retry after an event has already been persisted reuses the same lifecycle event and operation key, then attempts to finish the pending receipt/checkpoint work without creating a duplicate.

A dedicated recovery-receipt audit verifies the receipt hash chain, target and reconciliation bindings, optional Ed25519 attestation, signing-key cutoff, and external checkpoint freshness. After a signing-key rotation, the latest recovery receipt becomes stale. The explicit repair workflow may append a new receipt under the current key only when the original lifecycle event and its matching reconciliation receipt remain valid. Older receipts remain immutable for historical audit.

Checkpoint marker inspection/recovery uses a dedicated recovery-intent kind and short filesystem-safe IDs. Recovery is restricted to the exact anchored source snapshot; rollback, policy drift, multi-event gaps, or unproven continuity are not repaired automatically.

## Decision-gate integration and APIs

The attestation-lifecycle audit consumes the recovery-receipt audit. A required or configured recovery-receipt checkpoint that is not current makes the lifecycle evidence unavailable for current decisions. Corrupt or orphaned receipts are reported as unhealthy; missing legacy receipts are surfaced as repair-required and can be repaired only from matching persisted lifecycle and reconciliation evidence.

Application APIs:

- `auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts`
- `repairRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts`
- `getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointStatus`
- `reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpoint`
- `prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment`
- `applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment`
- `auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpoint`
- `inspectRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointRecovery`
- `recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpoint`

Authenticated HTTP routes cover receipt audit/repair, checkpoint status/reconciliation/enrollment/audit, and marker recovery inspection/application.

## Configuration

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_ATTESTATION_LIFECYCLE_RECOVERY_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_ATTESTATION_LIFECYCLE_RECOVERY_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_ATTESTATION_LIFECYCLE_RECOVERY_ANCHOR=true
```

When required, the provider must be configured and enrolled before lifecycle mutations. Private keys are not included in the source archive.

## Validation

- Batch 184 regression tests: 9/9 passed.
- Focused regressions for Batches 178–184: 54/54 passed.
- JavaScript/MJS/CJS syntax checks: 263/263 passed.
- Relative import references: 520 checked, zero missing.
- ZIP integrity and post-extraction SHA-256 equality are checked for the delivered archive.
- Full cumulative test-suite execution was attempted in bounded groups but exceeded the runtime limit in older test-file groups; it is not claimed as a single completed full-suite run.

No GitHub commit was made.
