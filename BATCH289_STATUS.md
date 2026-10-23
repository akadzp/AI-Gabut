# Batch 289 Status

Batch 289 adds a signed, recoverable renewal/revocation lifecycle for Batch 288 external attestations.

- Adds intent, renewed, revoked, superseded, finalized, and finalization-receipt event types with strict ledger schema validation.
- Requires the Batch 288 external-attestation audit to be `verified_current` before lifecycle mutation.
- Binds lifecycle phases and finalization receipts to challenge, target attestation, source Batch 287 lifecycle receipt, signing-key lifecycle, and checkpoint state.
- Adds idempotent apply/resume/reconcile behavior, terminal revocation, predecessor/replacement continuity, and missing-receipt recovery.
- Includes Batch 289 lifecycle events in the independent checkpoint inventory and overall recovery-gate convergence.
- Adds owner-scoped application APIs and HTTP routes for prepare, apply, audit, snapshot, and reconcile.
- Focused regression run passed 40/40 tests across Batch 102, artifact, and Batch 283–289 suites; Batch 104 passed separately 7/7.
- Full cumulative `npm test` was not run to completion; no full-suite PASS is claimed.
- Positive end-to-end renewal/revocation against a fully current Batch 288 attestation chain and direct HTTP listener startup remain unverified in this environment.
- No GitHub commit was made.
