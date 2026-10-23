# Agentic AI V4 — Batch 314 Release Notes

## Scope

Batch 314 adds external attestation for Batch 313 lifecycle finalization receipts. It preserves source receipt binding, cross-generation predecessor continuity, signing-key lifecycle verification, terminal-revocation propagation, and independent checkpoint recovery.

## Changes

- Added the Batch 314 signed external-attestation event and strict ledger schema validation.
- Added attestation, audit, snapshot, and reconcile service methods for Batch 313 lifecycle finalization receipts.
- Bound each attestation to its source finalization receipt, lifecycle finalization event, intent/action events, source receipt-chain prefix, checkpoint fingerprint, lifecycle audit digest, and signing-key lifecycle binding.
- Added deterministic operation IDs, predecessor continuity, missing-attestation detection, and recovery-aware checkpoint sequencing.
- Integrated Batch 314 into the independent checkpoint event inventory, application API, owner-scoped HTTP routes, and overall recovery-gate convergence.

## Validation

- Batch 314 regression suite: 4/4 PASS after final ZIP extraction.
- Focused final-extraction regression runs: 51/51 PASS across three separately completed TAP runs (23 baseline/application/artifact/lease tests, 24 Batch 309–313 tests, 4 Batch 314 tests).
- JavaScript/MJS/CJS syntax: 406/406 PASS after extraction.
- JSON parsing: 1/1 PASS.
- ZIP integrity and extracted-source SHA-256 parity: PASS.
- Full cumulative `npm test` is not claimed as passing.

No GitHub commit was made.
