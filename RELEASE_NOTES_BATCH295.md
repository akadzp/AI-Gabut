# Release Notes — Batch 295

## Renewal/revocation lifecycle for Batch 294 external attestations

- Added signed intent, renewal, revocation, supersession, finalization, and finalization-receipt event types for the Batch 294 external-attestation lifecycle.
- Added lifecycle challenge preparation and confirmation with owner scoping, TTL bounds, ledger-head binding, source-current gating, and signing-key lifecycle binding.
- Added predecessor/replacement continuity and terminal-revocation enforcement.
- Added lifecycle-specific finalization receipts with receipt-chain predecessor binding, lifecycle audit digest, checkpoint fingerprint, and key-cutoff metadata.
- Added idempotent phase operation IDs and reconciliation/resume behavior for interrupted lifecycle operations.
- Added schema validation and cumulative ledger/checkpoint inventory support for Batch 295 events.
- Added application wrappers that advance independent checkpoints, recover receipts, and reconcile Batch 294 source attestation state.
- Added five owner-scoped HTTP routes: `prepare`, `apply`, `audit`, `snapshot`, and `reconcile`.
- Integrated Batch 295 lifecycle status and generation-binding digest into overall recovery-gate convergence.

## Validation

- Focused regression tests: 47/47 PASS, including Batch 102, artifact tests, Batch 104, and Batch 290–295 suites.
- Batch 104 durable execution lease tests: 7/7 PASS.
- JavaScript/MJS/CJS syntax: 387/387 PASS.
- JSON parsing: 1/1 PASS.
- Full cumulative `npm test`: timed out after 300 seconds at subtest 1129 without a final TAP summary; not claimed as passing.
- ZIP integrity and extracted-source SHA-256 parity: PASS.
- Positive end-to-end lifecycle issuance and live HTTP listener startup are not claimed as tested.

No GitHub commit was made.
