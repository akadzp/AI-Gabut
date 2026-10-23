# Agentic AI V4 — Batch 322 Release Notes

## Added

- External attestation events for Batch 321 lifecycle finalization receipts.
- Canonical attestation binding over receipt identity/digest/generation, lifecycle finalization event, action and intent references, source receipt chain prefix, checkpoint fingerprint, lifecycle audit digest, and signing-key lifecycle binding.
- Predecessor attestation ID/digest continuity across attestation generations.
- Historical signature validation and current-key cutoff/revalidation audit.
- Idempotent attestation creation and owner-scoped attest/audit/snapshot/reconcile application APIs and HTTP routes.
- Independent checkpoint advancement before and after attestation, plus overall recovery-gate convergence integration.
- Six focused regression tests for empty history, no fabricated source receipts, binding validation, checkpoint inventory, application convergence/routes, and ledger schema.

## Safety behavior

- No external attestation is fabricated when Batch 321 finalization receipts are absent.
- Unhealthy source receipt chains and invalid receipt/finalization bindings block attestation.
- Missing attestations or a non-current required checkpoint require recovery.
- Invalid signatures, broken predecessor links, or binding mismatches produce an unhealthy audit.
- Terminal source revocation remains decision-blocking.

## Validation boundary

Selected regression tests and syntax/archive checks passed. The full cumulative test suite and fully provisioned positive end-to-end flow are not claimed as passing; see `BATCH322_VALIDATION_REPORT.md`.
