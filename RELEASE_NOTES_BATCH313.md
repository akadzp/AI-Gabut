# Agentic AI V4 — Batch 313 Release Notes

## Scope

Batch 313 adds a renewal/revocation lifecycle for Batch 312 external attestations. It preserves source receipt binding, cross-generation predecessor continuity, signing-key lifecycle verification, terminal revocation, finalization receipts, and independent checkpoint recovery.

## Changes

- Added Batch 313 lifecycle intent, renewed, revoked, superseded, finalized, and finalization-receipt event types with ledger schema validation.
- Added owner-scoped prepare/apply/audit/snapshot/reconcile APIs and HTTP routes under the Batch 312 external-attestation root.
- Bound lifecycle mutations to the active Batch 312 external attestation and its Batch 311 finalization receipt.
- Added deterministic operation IDs, idempotent phase recovery, predecessor/replacement checks, and terminal-revocation descendant rejection.
- Integrated Batch 313 events into independent checkpoint inventory and overall recovery-gate convergence.

## Validation

- Focused regression run: 47/47 PASS.
- Batch 313 regression suite: 5/5 PASS.
- JavaScript/MJS/CJS syntax and JSON parsing checked after packaging.
- ZIP integrity and extracted-file SHA-256 parity checked.
- Full cumulative `npm test` is not claimed as passing.

No GitHub commit was made.
