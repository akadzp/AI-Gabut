# Roadmap — Agentic AI V4 Batch 308

## Completed in this stage
- Batch 307 lifecycle finalization receipt external attestation.
- Receipt-chain prefix digest, finalization event binding, signing-key lifecycle binding, and predecessor attestation continuity.
- Missing-attestation recovery without fabricating source receipts.
- Independent checkpoint inventory and checkpoint-aware reconciliation.
- Overall recovery-gate convergence and owner-scoped HTTP routes.
- Focused regression tests and ZIP/source verification.

## Next stage: Batch 309
- Add renewal and terminal revocation lifecycle for Batch 308 external attestations.
- Bind intent/action/finalization/receipt events to the active Batch 308 attestation.
- Validate cross-generation predecessor/replacement links and replay protection.
- Recover interrupted lifecycle phases and missing finalization receipts.
- Preserve terminal revocation and signing-key cutoff semantics.
