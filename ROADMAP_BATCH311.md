# Roadmap — Batch 311

## Delivered
- Batch 311 lifecycle for Batch 310 external attestations.
- Signed renewal/revocation, supersession, finalization, and finalization receipts.
- Cross-generation predecessor continuity and replay/idempotency handling.
- Signing-key lifecycle and key-cutoff revalidation checks.
- Independent checkpoint-aware recovery and overall recovery-gate convergence.
- Owner-scoped lifecycle routes and focused regression tests.

## Follow-up work
- Run the complete cumulative `npm test` suite to a final TAP summary.
- Exercise a positive end-to-end Batch 310 external-attestation chain through Batch 311 renewal and revocation, finalization receipt creation, and checkpoint advancement.
- Exercise crash injection between every lifecycle and checkpoint phase.
- Validate live HTTP listener startup with runtime dependencies installed.
- Continue to Batch 312 only after this stage's validation artifacts are finalized; planned scope is external attestation for Batch 311 lifecycle finalization receipts.
