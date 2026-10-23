# Roadmap — After Batch 315

## Completed
Batch 315 implements renewal/revocation lifecycle management for Batch 314 external attestations, with finalization receipts, cross-generation continuity, key lifecycle binding, and checkpoint recovery.

## Next stage
**Batch 316 — External Attestation for Batch 315 Lifecycle Finalization Receipts, Cross-Generation Receipt Continuity, and Independent Checkpoint Recovery.**

## Follow-up validation
- Run the complete cumulative test suite to a final TAP summary.
- Add positive end-to-end provisioning for Batch 314 attestation → Batch 315 lifecycle → finalization receipt → external attestation.
- Exercise crash recovery at each lifecycle phase boundary.
- Run the HTTP listener with installed runtime dependencies and verify owner-scoped routes end to end.
