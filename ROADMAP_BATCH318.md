# Roadmap — After Batch 318

## Completed
Batch 318 adds external attestation for Batch 317 lifecycle finalization receipts, cross-generation continuity, signing-key lifecycle verification, and independent checkpoint recovery.

## Next stage
**Batch 319 — Renewal/Revocation Lifecycle for Batch 318 External Attestations, Cross-Generation Supersession, and Finalization Receipt Recovery.**

## Follow-up validation
- Run the full cumulative test suite to a final TAP summary.
- Provision a verified-current Batch 317 receipt chain, attest it in Batch 318, and exercise checkpoint advancement end to end.
- Exercise crash recovery at each boundary between receipt creation, attestation, and checkpoint advancement.
- Start the HTTP listener with installed runtime dependencies and verify owner-scoped routes end to end.
