# Agentic AI V4 — Batch 182

## Recovery-finalization receipt attestation

Batch 182 adds Ed25519 attestations to newly finalized decision-gate recovery receipts when a trusted finalization signer is available. The attestation binds the immutable finalization payload, completed recovery-intent reference, source checkpoint anchor, and signing-key lifecycle state. Required mode fails closed without a signer and trusted public key. Legacy schema-v1/v2 finalization records remain readable; required mode does not treat unattested legacy records as current evidence.

Attestation verification distinguishes a cryptographically valid historical receipt from evidence that is current for a decision. Key rotation or revocation leaves the historical signature verifiable when its signing-time lifecycle event is provable, but makes it historical-only. Invalid signatures, payload mismatches, or unprovable signing-time key state are rejected.

## External reconciliation receipts

Batch 182 introduces the independent trust domain `cross_domain_recovery_decision_gate_receipt_recovery_reconciliation_receipts`. Actual recovery-finalization checkpoint reconciliation and marker recovery can append an immutable reconciliation receipt containing before/after checkpoint state, operation identity, recovery-intent binding when available, key-lifecycle binding, and an Ed25519 attestation.

The reconciliation receipt ledger supports explicit enrollment, status, reconciliation, and audit. Its external checkpoint is independent of the finalization checkpoint. Receipt writes use optimistic CAS, deterministic operation keys, idempotent replay handling, and post-write integrity verification. Multi-event gaps, rollback, policy drift, invalid intent bindings, and ambiguous continuity fail closed.

When strict reconciliation anchoring is enabled, the reconciliation-receipt checkpoint must already be enrolled and current before mutating the finalization checkpoint. A receipt that is stored locally while its external checkpoint is pending is not eligible for current decisions.

## Decision-gate enforcement

The recovery decision gate now consumes recovery-finalization continuity findings. It blocks current decisions when finalization attestations are stale, signing-key lifecycle binding is stale, recovery-intent evidence is invalid, or a required reconciliation checkpoint is not current. Idempotent finalization paths recompute the current audit before reporting the result as usable.

## Configuration

```bash
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_FINALIZATION_ATTESTATION=true
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_FINALIZATION_ATTESTATION_MAX_AGE_MS=86400000
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_FINALIZATION_ATTESTATION_FUTURE_SKEW_MS=60000

AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_RECONCILIATION_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_RECONCILIATION_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_RECONCILIATION_ANCHOR=true
```

The reconciliation anchor endpoint must differ from all other trust-domain endpoints. Required anchoring fails closed without a provider and explicit enrollment. Enrollment does not retroactively prove non-empty local history.

## APIs

- `verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation`
- `auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationReceipts`
- `verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAttestation`
- `getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointStatus`
- `prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment`
- `applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment`
- `reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpoint`
- `auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpoint`

## Validation

- Batch 182 regression tests: 7/7 passed.
- Batch 178–182 focused regressions: 39/39 passed.
- Finalization receipt Ed25519 verification, key-cutoff staleness, independent reconciliation anchoring, reconciliation attestation, strict configuration, and decision-gate enforcement are covered.
- Syntax, import resolution, archive integrity, and extracted-source hash equality are checked before delivery.

No GitHub commit was made.

Cumulative validation after the final changes covered all 169 test files in bounded groups or individually: 1,236 test cases passed with zero failures. The five newest regression files (Batch 178–182) passed together at 39/39. Syntax checks passed for all 261 JavaScript/MJS/CJS files, and 514 relative import references were checked with zero missing targets.
