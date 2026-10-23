# Agentic AI V4 — Batch 312 Release Notes

## Scope

Batch 312 externally attests Batch 311 lifecycle finalization receipts and integrates those attestations with receipt continuity, signing-key lifecycle verification, independent checkpoint recovery, and the overall recovery gate.

## Changes

- Added `BATCH312_ATTESTED_EVENT` and its strict ledger schema validation.
- Added deterministic receipt-bound external attestation generation and idempotent reuse.
- Bound each attestation to the Batch 311 finalization receipt, finalization event, receipt-chain prefix digest, source checkpoint fingerprint, lifecycle audit digest, and signing-key lifecycle binding.
- Added predecessor attestation ID/digest continuity and signature-history validation.
- Added read-only snapshot and audit APIs plus reconciliation that resumes the Batch 311 source lifecycle before attesting.
- Added application wrappers, recovery-gate convergence status, and owner-scoped HTTP routes.
- Included Batch 312 events in the independent checkpoint inventory.

## Validation

- Focused regression run: 41/41 PASS.
- Batch 312 regression suite: 4/4 PASS.
- JavaScript/MJS/CJS syntax and JSON parsing checked after packaging.
- ZIP archive integrity and extracted-file SHA-256 parity checked.
- Full cumulative `npm test` is not claimed as passing.

No GitHub commit was made.
