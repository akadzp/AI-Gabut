# Agentic AI V4 — Batch 308

Batch 308 adds external attestation for Batch 307 lifecycle finalization receipts. Each attestation binds the receipt ID/digest/generation, lifecycle finalization event, action and challenge references, source receipt-chain prefix, checkpoint fingerprint, lifecycle audit digest, signing-key lifecycle binding, key-cutoff flags, and predecessor attestation.

The service reuses an attestation only when its complete current binding matches. New attestations form a predecessor chain and are reconciled with the independent checkpoint. Missing source receipts are never fabricated; invalid signature or binding causes an unhealthy audit, and terminal revocation remains decision-blocking.

Owner-scoped HTTP endpoints are available for attestation, audit, snapshot, and reconciliation. See `BATCH308_STATUS.md`, `BATCH308_VALIDATION_REPORT.md`, and `RELEASE_NOTES_BATCH308.md` for operational details and validation limits.
