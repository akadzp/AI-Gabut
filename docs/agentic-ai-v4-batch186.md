# Agentic AI V4 — Batch 186

## Recovery-intent external anchoring and continuity

Batch 186 adds an independent external snapshot checkpoint for the immutable bindings of attestation-lifecycle recovery intents. The checkpoint uses the dedicated domain `cross_domain_recovery_attestation_lifecycle_intents`, separate from the mutable intent lifecycle and from the reconciliation and recovery-receipt trust domains.

The external snapshot includes each intent's immutable identity, owner, sequence, previous-event digest, intent digest, binding, creation timestamp, and immutable event digest. Mutable `prepared`/`recovery_required`/`completed` status is audited against local lifecycle evidence separately; it is deliberately excluded from the anchored snapshot so completing an intent does not rewrite anchored history.

## Preflight, pending recovery, and orphan detection

When the new checkpoint is configured, lifecycle renewal/revocation challenges require an explicitly enrolled, fresh checkpoint with proven history and no policy drift. Applying a challenge persists or reuses the deterministic recovery intent, advances the intent checkpoint by at most one uniquely provable event, and only then creates a lifecycle event. If the external CAS fails, the intent remains pending and the lifecycle event is not created.

The pending-intent recovery API resumes the original challenge and intent. It never synthesizes a replacement challenge. Missing or mismatched challenges, duplicate intents, immutable-digest corruption, and completed intents without their lifecycle event are reported as orphaned/unhealthy and are not automatically reconstructed.

A signing-key lifecycle cutoff is rechecked before an operation without a persisted lifecycle event may proceed. If a pending intent crosses a key cutoff, the original challenge is stale and remains blocked for explicit disposition. If the lifecycle event already exists, recovery can finish the existing operation without duplicating receipts, while current-decision usability is independently revalidated.

Checkpoint recovery uses the exact external anchor and a separate marker-recovery intent kind. Rollback, policy drift, and multi-event gaps are not automatically repaired.

## Application API

- `getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointStatus`
- `reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpoint`
- `prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment`
- `applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment`
- `auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpoint`
- `inspectRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointRecovery`
- `recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpoint`
- `recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecyclePendingIntents`

Authenticated HTTP routes cover checkpoint status, reconciliation, enrollment, audit, marker recovery, and pending-intent recovery.

## Configuration

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_ATTESTATION_LIFECYCLE_INTENT_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_ATTESTATION_LIFECYCLE_INTENT_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_ATTESTATION_LIFECYCLE_INTENT_ANCHOR=true
```

The provider endpoint must be distinct from every other trust domain. Strict mode fails closed without a provider and requires explicit enrollment. Enrollment over non-empty pre-existing history preserves `historyNotProven`; it does not prove history retroactively. Private keys are not included in the archive.

## Validation

- Batch 186 regression tests: 16/16 passed.
- Batch 185–186 focused regressions: 24/24 passed.
- Batch 177–186 focused regressions: 87/87 passed.
- All 173 test files in the cumulative suite were completed in eight bounded groups: 1,275/1,275 passed. The single-process `npm test` invocation exceeded the 300-second environment limit, so the cumulative result is from the completed bounded runs.
- JavaScript/MJS/CJS syntax and relative import checks are validated for the delivered cumulative source archive.
- ZIP integrity and extracted-source SHA-256 equivalence are validated.
- HTTP listener startup remains unverified in this environment because `express` is not installed; route mapping and API-level tests are covered.

No GitHub commit was made.
