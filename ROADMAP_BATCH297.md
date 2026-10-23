# Roadmap — Batch 297

## Completed in this batch
- Batch 296 external-attestation renewal/revocation lifecycle.
- Signed intent/action/finalization/receipt chain with replay protection.
- Terminal revocation and descendant-generation rejection.
- Independent checkpoint and overall recovery-gate integration.
- Focused regression tests and archive validation.

## Next stage
Batch 298: external attestation for Batch 297 lifecycle finalization receipts, cross-generation receipt continuity, and independent checkpoint recovery.

## Remaining verification
- Run the complete cumulative test suite to a final TAP summary.
- Exercise an end-to-end current Batch 296 attestation through renewal and revocation.
- Validate HTTP listener startup in an environment with declared dependencies installed.
