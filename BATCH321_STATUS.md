# Batch 321 Status

Stage: implemented in the cumulative Batch 320 source tree.

Batch 321 adds a signed renewal/revocation lifecycle for Batch 320 external attestations. It includes predecessor/replacement supersession, terminal revocation, finalization receipts, signing-key lifecycle binding, challenge replay protection, source-receipt validation, owner-scoped API routes, and independent checkpoint/recovery-gate convergence.

Focused Batch 321 and cumulative regression tests, syntax checks, JSON parsing, archive integrity, clean extraction, and extracted-source SHA-256 comparisons are recorded in `BATCH321_VALIDATION_REPORT.md`.

The full cumulative `npm test`, live HTTP listener, crash-injection, and a fully provisioned positive end-to-end Batch 320 attestation-to-Batch 321 lifecycle flow are not claimed as passing unless explicitly reported as run.
