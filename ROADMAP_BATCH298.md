# Roadmap — Batch 298

## Completed in this batch
- External attestation for Batch 297 lifecycle finalization receipts.
- Cross-generation receipt and predecessor-attestation continuity checks.
- Signing-key lifecycle and key-cutoff verification.
- Independent checkpoint inventory and recovery-gate convergence.
- Owner-scoped API routes, focused regression tests, and ZIP validation.

## Next stage
Batch 299: renewal/revocation lifecycle for Batch 298 external attestations, cross-generation supersession, and finalization receipt recovery.

## Remaining verification
- Run the full cumulative test suite to a final TAP summary.
- Exercise a positive end-to-end Batch 297 lifecycle receipt through Batch 298 external attestation with an enabled independent checkpoint.
- Validate live HTTP listener startup in an environment with declared dependencies installed.
