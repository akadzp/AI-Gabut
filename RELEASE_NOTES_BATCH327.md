# Agentic AI V4 — Batch 327 Release Notes

## Added

- Renewal/revocation lifecycle for Batch 326 external attestations.
- Signed predecessor/replacement continuity across lifecycle generations.
- Finalization receipts bound to lifecycle intent, action, key lifecycle, and checkpoint fingerprints.
- Recovery of interrupted lifecycle phases and missing finalization receipts.
- Owner-scoped application methods and HTTP routes for prepare, apply, audit, snapshot, and reconcile.
- Batch 327 ledger schema validation, checkpoint inventory, and overall recovery-gate convergence.
- Six focused regression tests.

## Safety behavior

- No lifecycle event or receipt is fabricated when Batch 326 source attestations are absent.
- Lifecycle mutation requires a healthy, current Batch 326 attestation chain and usable independent checkpoint.
- Invalid bindings, signatures, predecessor continuity, or signing-key lifecycle state fail closed.
- Terminal revocation remains decision-blocking and cannot be undone by renewal.
- Interrupted phases remain recoverable rather than being reported as current.

## Validation boundary

See `BATCH327_VALIDATION_REPORT.md` for measured regression, syntax, and archive checks. Full cumulative `npm test` and full positive end-to-end provisioning are not claimed unless explicitly reported there.
