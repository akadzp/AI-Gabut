# Agentic AI V4 — Batch 300

Batch 300 adds external attestation for Batch 299 lifecycle finalization receipts.

## Evidence model
Each attestation is bound to the source receipt ID/digest/generation, lifecycle finalization event ID/digest, challenge/action, target and source receipt references, intent/action event digests, replacement reference where applicable, receipt-binding digest, source receipt-chain prefix digest, checkpoint fingerprint, lifecycle audit digest, source/current signing-key lifecycle bindings, key-cutoff flags, and predecessor attestation ID/digest.

## Audit and recovery
The audit verifies historical signatures, source receipt and finalization-event linkage, generation sequence, predecessor continuity, canonical binding digest, receipt-chain prefix digest, key-cutoff consistency, and checkpoint usability. Missing attestations are reported as recovery-required. Invalid signatures or broken bindings are unhealthy. Terminal source revocation remains decision-blocked.

Reconciliation first validates and reconciles Batch 299 lifecycle receipts, advances the independent checkpoint before attestation when required, creates or reuses attestations idempotently, advances the checkpoint again, and runs the final audit.

## API surface
The Batch 300 root is derived from the Batch 299 external-attestation lifecycle root and adds `/finalization-receipts/external-attestations`. It exposes `POST /attest`, `GET /audit`, `GET /snapshot`, and `POST /reconcile` under the application's authenticated owner scope.
