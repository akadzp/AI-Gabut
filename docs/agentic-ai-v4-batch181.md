# Agentic AI V4 — Batch 181

## Recovery-finalization ledger external anchoring

Batch 181 adds the independent trust domain `cross_domain_recovery_decision_gate_receipt_recovery_finalizations`. The checkpoint protects the append-only CAS recovery-finalization ledger independently from the source decision-gate receipt checkpoint and receipt-attestation checkpoint.

The new checkpoint supports explicit enrollment, status, freshness checks, one-event continuity reconciliation, integrity audit, marker-recovery inspection, and recovery. Reconciliation rejects multi-event gaps, policy drift, rollback, unhealthy sources, and ambiguous continuity. A fresh empty genesis baseline may be enrolled and recovered without inventing history; recovery intents now use filesystem-safe IDs for this trust domain.

## Recovery-intent CAS binding

New finalization receipts use schema version 2 and bind:

- the completed recovery-intent ID, recovery-intent digest, and immutable intent-event digest;
- the source decision-receipt checkpoint anchor, sequence, snapshot digest, and count;
- the receipt-attestation source snapshot digest and attestation checkpoint binding;
- the current signing-key lifecycle binding digest;
- the deterministic operation key and postcondition digest.

A supplied recovery intent must be persisted, owner-scoped, digest-valid, and `completed`; an intent with a mismatched or missing record is rejected before the finalization ledger is written. Existing schema-version-1 finalization receipts remain auditable using their original postcondition formula.

## Key-cutoff and receipt continuity audit

`auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationContinuity` checks finalization-ledger integrity, external checkpoint usability, receipt-attestation signatures and current status, recovery-intent bindings, and the current signing-key lifecycle digest. Key rotation or cutoff can make a previously finalized receipt stale without invalidating its historical digest. The recovery decision gate reports continuity findings and, when strict external finalization anchoring is required, blocks decisions while the finalization ledger is not current.

## Configuration

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_FINALIZATION_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_FINALIZATION_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_FINALIZATION_ANCHOR=true
```

The endpoint must be distinct from every other trust-domain endpoint. Required mode fails closed without a provider. Explicit enrollment is required before a strict finalization write can be accepted. Enrolling a non-empty legacy ledger does not establish retroactive trust; it remains `historyNotProven`.

## APIs

- `getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointStatus`
- `prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment`
- `applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment`
- `reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpoint`
- `auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpoint`
- `inspectRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointRecovery`
- `recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpoint`
- `auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationContinuity`

## Validation

- Batch 181 regression tests: 7/7 passed.
- Batch 178–181 regression tests: 32/32 passed.
- All 168 test files were exercised in bounded groups or individually after the final code changes: 1,224 test cases passed, zero failures. One oversized grouped invocation was terminated by the environment while running Batch 169/170 workers; those files were rerun individually and passed, as did all remaining files in bounded runs.
- JavaScript/MJS/CJS syntax: 260/260 passed.
- Relative import references: 511 checked, zero missing.
- ZIP integrity and extracted-source SHA-256 equivalence were checked before delivery.

No GitHub commit was made.
