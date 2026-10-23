# Release Notes — Batch 293

- Added renewal/revocation lifecycle operations for Batch 292 external attestations.
- Added signed intent, renewal, revocation, supersession, finalization, and finalization-receipt event types.
- Bound lifecycle operations to the active Batch 292 attestation, source finalization receipt, generation, challenge, signing-key lifecycle, and checkpoint state.
- Added predecessor/replacement continuity, terminal-revocation enforcement, deterministic operation IDs, and replay-safe recovery.
- Added finalization-receipt chain validation, missing-receipt recovery, key-cutoff checks, and independent checkpoint reconciliation.
- Added Batch 293 event schema validation and independent checkpoint inventory coverage.
- Integrated Batch 293 status and generation-binding digest into overall recovery-gate convergence.
- Added owner-scoped prepare/apply/audit/snapshot/reconcile application APIs and HTTP routes.
- Added Batch 293 focused regression tests and technical documentation.
- No GitHub commit was made.
