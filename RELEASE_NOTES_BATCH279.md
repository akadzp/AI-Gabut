# Release Notes — Agentic AI V4 Batch 279

Batch 279 adds a signed, recoverable renewal/revocation lifecycle for Batch 278 external attestations.

## Included
- Intent, renewed, revoked, superseded, finalized, and finalization-receipt event types.
- Owner-scoped prepare/apply/audit/snapshot/reconcile application APIs and HTTP routes.
- Target binding to the current Batch 278 external attestation and its Batch 277 lifecycle finalization receipt.
- Monotonic lifecycle generations, deterministic phase operation IDs, signed append-only ledger events, and replay/binding validation.
- Renewal predecessor/replacement chain checks and terminal revocation enforcement.
- Finalization receipt chaining, key-cutoff detection/revalidation, checkpoint-aware recovery, and global recovery-gate convergence.
- Focused Batch 279 regression tests and technical documentation.

## Validation scope
Focused regression tests, syntax parsing, API-reference/import checks, archive integrity, and extracted-source equality were validated. The full cumulative `npm test` suite and a complete positive end-to-end lifecycle chain were not claimed as passed.
