# Agentic AI V4 — Batch 183

## Recovery-finalization attestation renewal and revocation

Batch 183 adds an append-only lifecycle ledger for immutable recovery-finalization and reconciliation receipts. Renewal creates a new Ed25519 attestation over the original receipt payload under the currently active signing key; the original receipt and original signature are never overwritten. The renewal attestation has its own identifier and is bound to the original receipt ID, kind, and payload digest. Revocation appends a lifecycle event that blocks current use while preserving historical evidence.

Lifecycle changes require a short-lived, owner-scoped challenge. The challenge binds the exact target receipt digest, original attestation digest, current lifecycle snapshot, signing-key lifecycle binding, and reconciliation checkpoint state. Challenges expire after ten minutes. A target with invalid historical signature, changed digest, stale challenge, revoked state, or mismatched binding is rejected. A revoked target cannot be renewed through the same workflow.

The lifecycle ledger is anchored indirectly through an immutable reconciliation receipt in the independently configured recovery-reconciliation checkpoint domain. A renewal is considered current only when its Ed25519 signature is valid, the signing-key lifecycle is current, the lifecycle event is covered by a reconciliation receipt, and that receipt checkpoint is anchored and fresh. Revocation fails closed even if its external receipt is temporarily pending.

## Reconciliation checkpoint crash recovery

Batch 183 exposes inspection and recovery APIs for the recovery-reconciliation receipt checkpoint marker. Marker recovery uses a dedicated recovery-intent kind, validates the exact external anchor and source snapshot, and remains blocked for rollback, policy drift, unproven continuity, or unsafe gaps.

Reconciliation receipt writes are now retryable after the local receipt has been persisted but the external checkpoint update has not completed. A retry locates the same operation key, checks the stored postcondition, and reconciles the existing receipt instead of appending a duplicate. Multi-event gaps are not automatically repaired.

## Persisted postcondition and decision-gate enforcement

The reconciliation audit validates lifecycle-receipt postconditions against the actual persisted lifecycle event, including event digest, action, sequence, target binding, and the snapshot-prefix digest that was anchored. It also checks a finalization checkpoint postcondition when a receipt references the currently observed anchor sequence.

The finalization verifier consults lifecycle events without mutating the original receipt. A revoked attestation is never current. A renewed attestation can restore current status only after signature, key-lifecycle, freshness, and reconciliation-anchor checks pass. The cross-domain continuity audit and decision gate consume these results; stale, unanchored, revoked, or unhealthy evidence cannot authorize a current decision.

## APIs

- `auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle`
- `prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle`
- `applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle`
- `inspectRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointRecovery`
- `recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpoint`

Authenticated HTTP routes are added for lifecycle audit, challenge preparation/application, and reconciliation checkpoint recovery inspection/application.

## Validation

- Batch 183 regression tests: 6/6 passed.
- Batch 178–183 focused regressions: 45/45 passed.
- All 170 test files executed in bounded groups: 1,242 test cases passed, zero failures.
- JavaScript/MJS/CJS syntax and relative-import resolution are checked for the complete cumulative source tree.
- ZIP integrity and post-extraction source hashes are verified.

No GitHub commit was made.
