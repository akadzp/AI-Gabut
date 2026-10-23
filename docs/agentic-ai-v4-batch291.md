# Agentic AI V4 — Batch 291

Batch 291 implements renewal and terminal revocation for Batch 290 external attestations. It introduces lifecycle intent, renewal, revocation, supersession, finalization, and finalization-receipt events. Operations are owner-scoped, challenge-confirmed, generation-bound, idempotent, and recorded in the signed append-only proof-continuity ledger.

The lifecycle checks the Batch 290 external-attestation source audit before mutation, binds the active target and its source finalization receipt, verifies signing-key lifecycle state, and prevents new operations after terminal revocation. Renewal records a predecessor/replacement chain. Each finalized lifecycle generation requires a receipt that binds its finalization event and prior receipt.

Batch 291 events are included in ledger schema validation and the independent checkpoint inventory. Application wrappers advance checkpoints after lifecycle phases and reconcile pending phases and missing receipts. Global recovery-gate convergence now includes Batch 291 status and generation-binding digest. Five owner-scoped HTTP routes expose prepare, apply, audit, snapshot, and reconcile operations.

## Verification boundaries

Focused regression tests and cumulative syntax/import checks are recorded in `BATCH291_VALIDATION_REPORT.md`. A complete positive end-to-end renewal/revocation flow from a verified-current Batch 290 source was not exercised. The full cumulative test suite and live HTTP listener are not claimed as passing.
