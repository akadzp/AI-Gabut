# Agentic AI V4 — Batch 328 Release Notes

## Added

- Signed external attestations for Batch 327 lifecycle finalization receipts.
- Receipt-prefix continuity across generations, including predecessor attestation ID/digest bindings.
- Validation of finalization event, source receipt, lifecycle audit, checkpoint fingerprint, and signing-key lifecycle bindings.
- Idempotent attestation creation and recovery for interrupted receipt-to-attestation processing.
- Independent checkpoint reconciliation and Batch 328 overall recovery-gate convergence.
- Owner-scoped application methods and HTTP endpoints for attest, audit, snapshot, and reconcile.
- Batch 328 ledger schema validation, cumulative event inventory, and six focused regression tests.

## Safety behavior

- Empty source history remains read-only and does not fabricate receipts or attestations.
- External attestation requires a healthy/current Batch 327 lifecycle receipt chain and a usable independent checkpoint.
- Invalid signatures, receipt bindings, predecessor continuity, or signing-key lifecycle state fail closed.
- Terminal revocation remains decision-blocking; external attestation does not reactivate revoked sources.
- Interrupted reconciliation remains pending/recovery-required until source, attestation, and checkpoint state converge.

## Validation boundary

See `BATCH328_VALIDATION_REPORT.md` for measured selected-regression, syntax, JSON, and archive checks. Full cumulative `npm test`, a fully provisioned positive end-to-end flow, live listener startup, and exhaustive crash-injection are not claimed as verified.
