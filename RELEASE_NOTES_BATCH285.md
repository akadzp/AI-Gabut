# Release Notes — Batch 285

- Added a signed renewal/revocation lifecycle for Batch 284 external attestations.
- Added intent, renewal, revocation, supersession, finalization, and finalization-receipt ledger events.
- Bound lifecycle phases and receipts to the active Batch 284 attestation, source finalization receipt, signing-key lifecycle, and independent checkpoint fingerprint.
- Added predecessor/replacement continuity, terminal revocation enforcement, operation-id idempotency, key-cutoff checks, and fail-closed audit findings.
- Added owner-scoped prepare/apply/audit/snapshot/reconcile APIs and HTTP routes.
- Added Batch 285 to the append-only ledger schema, independent checkpoint inventory, and overall recovery-gate convergence.
- Added Batch 285 regression tests for empty-history safety, source-current gating, API/route wiring, checkpoint inventory, and malformed lifecycle schema.
- No GitHub commit was made.
