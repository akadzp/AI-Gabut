# Batch 285 Roadmap

## Scope

Renewal/revocation lifecycle for Batch 284 external attestations, cross-generation supersession, finalization receipts, and independent checkpoint recovery.

## Implemented

- Signed lifecycle intent, renewal, revocation, supersession, finalization, and finalization-receipt events.
- Batch 284 source-attestation and source-receipt binding validation.
- Monotonic lifecycle generations and predecessor/replacement checks.
- Terminal revocation enforcement and replay-resistant operation IDs.
- Signing-key cutoff detection and revalidation binding.
- Checkpoint-aware application reconciliation and overall recovery-gate convergence.
- Owner-scoped HTTP endpoints and regression tests.

## Follow-up validation

- Exercise a positive end-to-end flow from a fully current Batch 284 attestation through Batch 285 renewal/revocation and finalization receipt creation.
- Complete the cumulative test suite to a final TAP summary; the current environment timed out during the full suite after 1,129 subtests had started/completed without a visible failure, but did not produce a final summary.
- Run an HTTP listener smoke test in an environment with Express installed.
