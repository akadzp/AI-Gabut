# Agentic AI V4 — Batch 325

Batch 325 renews or terminally revokes Batch 324 external attestations. Each lifecycle phase is append-only and bound to a deterministic challenge, target attestation digest/generation, Batch 323 finalization receipt, reason digest, signing-key lifecycle binding, and independent checkpoint state.

Renewal creates a replacement and an explicit supersession link; revocation is terminal. Finalization receipts bind the lifecycle finalization event, phase digests, source receipt, checkpoint fingerprint, signing-key binding, and predecessor receipt. Reconciliation resumes persisted phases without fabricating source receipts and advances checkpoints before declaring convergence.

The service is integrated into the overall recovery gate and exposed through owner-scoped HTTP endpoints under the Batch 324 external-attestation root. Regression coverage and validation limitations are in `BATCH325_VALIDATION_REPORT.md`.
