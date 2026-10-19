# Agentic AI V4 — Batch 254 Release Notes

## Scope

Batch 254 adds signed external attestations for Batch 253 lifecycle finalization receipts, including cross-generation receipt continuity, predecessor-attestation chaining, signing-key cutoff validation, terminal-revocation propagation, and independent-checkpoint recovery.

## New event

`proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch253_lifecycle_finalization_receipt_external_attested`

## Application API

- `attestRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestations`
- `auditRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestations`
- `getRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestationSnapshot`
- `reconcileRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestations`

## HTTP routes

Under `/finalization-receipts/external-attestations/lifecycle/finalization-receipts/external-attestations`:

- `POST /attest`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

## Safety properties

- No external attestation is fabricated when no source lifecycle finalization receipt exists.
- Source lifecycle receipts must pass audit and currentness checks before attestation.
- Attestation binding covers source receipt, finalization event, action/intent evidence, receipt-chain prefix, checkpoint fingerprint, lifecycle audit digest, and signing-key lifecycle state.
- Attestations form a monotonically increasing predecessor chain.
- Missing attestations or stale checkpoints require recovery; invalid signatures or chain bindings are unhealthy; terminal revocation remains decision-blocked.
- Checkpoint advancement is performed before and after attestation during reconciliation.

## Validation

Focused Batch 254 regression tests, syntax/import validation, and ZIP integrity checks are run against the extracted final archive. Full cumulative suite status is reported separately and is not inferred from focused test results.

## Inherited compatibility correction

This batch also corrects a prior event-type mismatch in the Batch 250 attestation writer: it now appends `BATCH250_ATTESTED_EVENT`, matching the Batch 250 auditor's event filter. A regression guard prevents the writer from reclassifying Batch 250 attestations as Batch 248 events.
