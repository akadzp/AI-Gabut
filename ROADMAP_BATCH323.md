# Agentic AI V4 Roadmap — After Batch 323

## Completed in this stage

Batch 323 adds renewal/revocation lifecycle control for Batch 322 external attestations, cross-generation supersession, lifecycle finalization receipts, source receipt and signature checks, signing-key cutoff handling, and independent checkpoint/recovery-gate convergence.

## Next stage

**Batch 324 — External Attestation for Batch 323 Lifecycle Finalization Receipts, Cross-Generation Receipt Continuity, and Independent Checkpoint Recovery.**

Priorities:
1. Signed external attestations for Batch 323 lifecycle finalization receipts.
2. Receipt-to-finalization-event and receipt-prefix digest verification.
3. Predecessor attestation continuity across generations.
4. Signing-key cutoff/revalidation and historical signature checks.
5. Independent checkpoint recovery before and after attestation writes.
6. Focused regression coverage plus complete local ZIP, syntax, and archive verification.

The workflow remains cumulative, one stage per run, with a complete local-application ZIP and no GitHub commit.
