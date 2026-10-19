# Release Notes — Batch 266

- Added signed external attestations for Batch 265 lifecycle finalization receipts.
- Added canonical binding validation for receipt identity/digest/generation, lifecycle finalization event, receipt-chain prefix, checkpoint fingerprint, audit digest, signing-key lifecycle, and predecessor continuity.
- Added deterministic idempotent attestation writes and missing-attestation recovery.
- Added owner-scoped attest/audit/snapshot/reconcile APIs and HTTP routes.
- Added Batch 266 events to independent checkpoint snapshots and global recovery-gate convergence.
- Added focused regression tests for empty history, API wiring, and ledger schema validation.
