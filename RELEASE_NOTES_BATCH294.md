# Release Notes — Batch 294

## External attestation for Batch 293 lifecycle finalization receipts

- Added `BATCH294_ATTESTED_EVENT` and schema validation for its signed binding.
- Added attestation creation, audit, snapshot, and reconciliation functions for Batch 293 finalization receipts.
- Bound attestations to lifecycle finalization events, receipt digests and generations, receipt-chain prefix digest, challenge/action lineage, replacement binding, checkpoint fingerprint, lifecycle audit digest, signing-key lifecycle binding, key-cutoff state, and predecessor attestation.
- Added idempotent operation IDs and strict receipt/chain/signature checks.
- Added checkpoint-aware application convergence and four owner-scoped HTTP routes (`attest`, `audit`, `snapshot`, `reconcile`).
- Integrated Batch 294 status and generation-binding digest into overall recovery-gate convergence.
- Ensured the independent checkpoint inventory includes Batch 294 events.
- Retained Batch 293 source lifecycle event types in the cumulative ledger allowlist so the source receipts can be validated alongside Batch 294 attestations.

## Validation

- Focused regression tests: 32/32 PASS.
- Batch 104 durable execution lease regression suite: 7/7 PASS.
- JavaScript/MJS/CJS syntax: 386/386 PASS.
- JSON parsing: 1/1 PASS.
- ZIP integrity and extracted-source hash parity: PASS.
- Full cumulative `npm test` and positive end-to-end attestation issuance are not claimed as passing.

No GitHub commit was made.
