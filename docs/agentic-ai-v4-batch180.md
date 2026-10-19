# Agentic AI V4 — Batch 180

## Recovery decision-gate receipt attestation external anchoring

Batch 180 adds the trust domain `cross_domain_recovery_decision_gate_audit_receipt_attestations`, independent from the decision-gate receipt ledger checkpoint. The snapshot binds each receipt sequence and digest to its attestation payload/signature, signing-key ID and lifecycle cutoff, policy-state digest, and issuance time. Legacy unattested receipts are represented explicitly rather than silently omitted.

The checkpoint supports explicit enrollment, status, bounded one-event continuity reconciliation, integrity audit, marker recovery inspection, and marker recovery. Required mode fails closed without a provider. An empty genesis snapshot may be explicitly enrolled without marking nonexistent prior history as unproven. Enrollment of a non-empty local history remains `historyNotProven`; it does not establish retroactive trust.

Attestation verification now checks the independent attestation checkpoint when configured. It continues to revalidate the receipt signature, expiry, policy-state digest, and signing-key lifecycle. A historically valid signature is not current when the signing key is cut off, the attestation is expired, or the required external checkpoint is stale/unhealthy.

## Recovery receipt finalization CAS guard

A local append-only finalization ledger records the postcondition after decision-gate receipt checkpoint recovery. Each finalization receipt binds the external anchor digest and sequence, receipt source snapshot digest/count, source ledger head, and attestation-checkpoint binding where configured. Deterministic operation keys plus optimistic compare-and-set and bounded retries make repeated finalization idempotent. Invalid ledgers, rollback, policy drift, stale anchors, and inconsistent postconditions fail closed.

The finalization ledger is local in Batch 180; it is not claimed to have its own independent external anchor. Its usability remains dependent on current source/checkpoint verification.

## Configuration

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_AUDIT_RECEIPT_ATTESTATION_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_AUDIT_RECEIPT_ATTESTATION_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_DECISION_GATE_AUDIT_RECEIPT_ATTESTATION_ANCHOR=true
```

The endpoint must be distinct from every other trust-domain endpoint. Required mode rejects startup if the provider is absent.

## APIs

- `getRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointStatus`
- `prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointEnrollment`
- `applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointEnrollment`
- `reconcileRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpoint`
- `auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpoint`
- `inspectRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointRecovery`
- `recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpoint`
- `auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizations`
- `finalizeRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryCAS`

## Validation

- Batch 180 tests: 6/6 pass.
- Batch 178–180 tests: 25/25 pass.
- Batch 165–180 focused tests: 99/99 pass across bounded grouped runs.
- All 167 test files were exercised in bounded groups; 1,222 assertions passed, zero failures in completed file-level runs. One oversized multi-file invocation exceeded the runtime limit; the individual file groups completed separately.
- JavaScript/MJS/CJS syntax: 259/259 pass.
- Relative import references: 508 checked, zero missing.
- ZIP integrity and extracted-file SHA-256 equivalence: pass.

No GitHub commit was made.
