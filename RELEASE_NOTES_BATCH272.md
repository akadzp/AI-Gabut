# Release Notes — Batch 272

- Added signed external attestation for Batch 271 lifecycle finalization receipts.
- Bound each attestation to the receipt, lifecycle finalization event, source receipt-chain prefix, checkpoint fingerprint, audit digest, and signing-key lifecycle.
- Added monotonic attestation generations and predecessor ID/digest continuity.
- Added fail-closed source receipt, signature, binding, and key-cutoff verification.
- Added independent checkpoint snapshot coverage and pre/post-attestation checkpoint advancement.
- Added owner-scoped attest/audit/snapshot/reconcile APIs and global recovery-gate convergence.
- Added focused regression tests for empty-history behavior, API/checkpoint wiring, and schema binding validation.
- No GitHub commit was made.
