# Agentic AI V4 — Batch 326 Release Notes

## Added

- External attestation service for Batch 325 lifecycle finalization receipts.
- Canonical bindings for receipt/finalization identity, lifecycle action, receipt-chain prefix, source checkpoint, source/current signing-key lifecycle digests, key-cutoff state, and predecessor attestation continuity.
- Deterministic attestation operation IDs, safe reuse for unchanged bindings, and append-only replacement attestations when bindings change.
- Audit checks for source receipt coverage, finalization-event matching, signatures, predecessor continuity, key-cutoff revalidation, terminal revocation, and checkpoint usability.
- Reconciliation through source lifecycle recovery, pre-attestation checkpoint advancement, attestation, post-attestation checkpoint advancement, and final audit.
- Owner-scoped application methods and HTTP endpoints for attest, audit, snapshot, and reconcile.
- Batch 326 ledger schema validation, independent checkpoint inventory, and overall recovery-gate convergence.
- Six focused Batch 326 regression tests. Older Batch 322 and Batch 324 allowlist assertions were updated to account for the cumulative Batch 326 event-type inventory.

## Safety behavior

- No external attestation is fabricated when Batch 325 lifecycle finalization receipts are absent.
- Attestation is rejected if source lifecycle receipts are unhealthy, incomplete, or not current.
- Broken receipt/finalization binding, invalid signature, predecessor mismatch, and key-lifecycle inconsistencies fail closed.
- Terminal revocation remains decision-blocking; external attestation does not reactivate a revoked source.
- Missing checkpoint or attestation phases remain recoverable rather than being reported as current.

## Validation boundary

Selected regression tests and syntax/archive checks passed. Full cumulative `npm test`, a fully provisioned positive end-to-end attestation flow, crash injection at every phase boundary, and live HTTP listener startup are not claimed as passing. See `BATCH326_VALIDATION_REPORT.md`.
