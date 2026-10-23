# Agentic AI V4 — Batch 310

Batch 310 adds external attestation for Batch 309 lifecycle finalization receipts.

## Data binding
Each attestation binds the source finalization receipt and lifecycle finalization event, challenge and action, target attestation, source receipt, intent and action events, optional replacement attestation, receipt binding digest, receipt-chain prefix digest, checkpoint fingerprint, lifecycle audit digest, source/current signing-key lifecycle binding, key-cutoff state, and predecessor attestation ID/digest.

## Audit and recovery
The audit checks source receipt existence, finalization linkage, generation continuity, predecessor continuity, signature history, binding digest, checkpoint usability, and key lifecycle status. Missing attestations require recovery; invalid chain or signature state is unhealthy; a terminal source revocation remains decision-blocking. Reconciliation advances the source checkpoint before attestation where required, creates or reuses attestations idempotently, advances the checkpoint again, then audits the final state.

## API
The owner-scoped root is nested under the Batch 309 external-attestation lifecycle path and exposes `POST /attest`, `GET /audit`, `GET /snapshot`, and `POST /reconcile`.

## Validation
Four Batch 310 tests pass. Focused regression suites for Batch 102, artifacts, Batch 104, and Batches 306–310 passed when run separately. The full cumulative test suite and positive end-to-end chain provisioning are not claimed as complete. No GitHub commit was made.
