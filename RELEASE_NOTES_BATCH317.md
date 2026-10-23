# Release Notes — Agentic AI V4 Batch 317

- Added Batch 317 intent, renewal, revocation, supersession, finalization, and finalization-receipt event types for Batch 316 external attestations.
- Added owner-scoped prepare/apply/audit/snapshot/reconcile service methods and HTTP routes below the Batch 316 external-attestation root.
- Bound lifecycle mutation to a verified-current Batch 316 external attestation and its Batch 315 finalization receipt.
- Added monotonic generation checks, predecessor/replacement binding, signature verification, signing-key cutoff handling, terminal-revocation enforcement, and deterministic phase operation IDs.
- Added finalization-receipt continuity checks, independent checkpoint inventory, resumable reconciliation, and overall recovery-gate convergence.
- Added six focused Batch 317 regression tests.
- No GitHub commit was made.
