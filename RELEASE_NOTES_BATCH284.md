# Release Notes — Batch 284

- Added a signed external attestation layer for Batch 283 lifecycle finalization receipts.
- Bound each attestation to the source receipt, lifecycle finalization event, receipt-chain prefix, source checkpoint, lifecycle audit, and signing-key lifecycle.
- Added cross-generation predecessor validation, key-cutoff revalidation, and fail-closed receipt/signature auditing.
- Added idempotent attestation, read-only snapshot, audit, and checkpoint-aware reconciliation wrappers.
- Added owner-scoped HTTP endpoints and included Batch 284 in the independent checkpoint inventory and overall recovery-gate convergence.
- Added regression tests for empty-history safety, API/route wiring, checkpoint coverage, and malformed binding rejection.
- No GitHub commit was made.
