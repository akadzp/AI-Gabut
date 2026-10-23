# Roadmap — After Batch 317

## Completed
Batch 317 implements renewal/revocation lifecycle management for Batch 316 external attestations, with finalization receipts, cross-generation continuity, key lifecycle binding, and checkpoint recovery.

## Next stage
**Batch 318 — External Attestation for Batch 317 Lifecycle Finalization Receipts, Cross-Generation Receipt Continuity, and Independent Checkpoint Recovery.**

## Follow-up validation
- Run the full cumulative test suite to a final TAP summary.
- Add positive end-to-end provisioning through a verified-current Batch 316 attestation, Batch 317 renewal/revocation, finalization receipt, and independent checkpoint advancement.
- Exercise crash recovery at each lifecycle phase boundary, including receipt creation and checkpoint advancement.
- Run the HTTP listener with installed runtime dependencies and verify owner-scoped routes end to end.
