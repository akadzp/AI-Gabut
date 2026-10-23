# Agentic AI V4 — Batch 329 Release Notes

## Added

- Renewal and terminal-revocation lifecycle for Batch 328 external attestations.
- Challenge-bound intent, renewed/revoked, superseded, finalized, and finalization-receipt events.
- Signed predecessor/replacement continuity and monotonic lifecycle generations.
- Receipt bindings for source attestation, source Batch 327 finalization receipt, lifecycle audit digest, checkpoint fingerprint, and signing-key lifecycle state.
- Idempotent lifecycle phase recovery and pending-challenge reconciliation.
- Independent checkpoint advancement through the application wrapper.
- Owner-scoped prepare, apply, audit, snapshot, and reconcile HTTP routes.
- Batch 329 schema validation, cumulative event inventory, overall recovery-gate convergence, and six focused regression tests.

## Safety behavior

- Empty source history remains read-only and does not fabricate lifecycle events or receipts.
- Lifecycle mutation requires a `verified_current` Batch 328 external-attestation chain and a usable independent checkpoint.
- Unsupported actions, malformed reasons, invalid TTLs, stale challenges, changed ledger heads, invalid signatures, and broken receipt/predecessor bindings fail closed.
- Terminal revocation remains decision-blocking; the lifecycle does not reactivate a revoked attestation.
- Interrupted operations remain pending/recovery-required until source, lifecycle, finalization receipt, and checkpoint state converge.

## Validation boundary

See `BATCH329_VALIDATION_REPORT.md` for measured focused regression, syntax, JSON, and archive checks. Full cumulative `npm test`, a fully provisioned positive end-to-end flow, live listener startup, and exhaustive crash-injection are not claimed as verified.
