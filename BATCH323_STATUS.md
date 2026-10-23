# Batch 323 Status

Stage: implemented in the cumulative Batch 322 source tree.

Batch 323 adds a renewal/revocation lifecycle for Batch 322 external attestations. It includes signed lifecycle intent/action/finalization events, predecessor-to-replacement supersession, terminal revocation, lifecycle finalization receipts, deterministic operation IDs, challenge confirmation and expiry checks, signing-key cutoff/revalidation binding, source receipt validation against Batch 321 lifecycle receipts, independent checkpoint recovery, owner-scoped application methods and HTTP routes, and overall recovery-gate convergence.

Selected Batch 309–323 regression tests, Batch 102 application/dependency checks, artifact persistence tests, and Batch 104 durable execution lease tests were run against the source tree. Syntax and JSON checks passed. See `BATCH323_VALIDATION_REPORT.md` for the precise validation boundary.

The full cumulative `npm test`, live HTTP listener startup with all runtime dependencies provisioned, crash-injection at every phase boundary, and a fully provisioned positive end-to-end Batch 322 attestation → Batch 323 renewal/revocation → receipt/checkpoint flow are not claimed as passing.
