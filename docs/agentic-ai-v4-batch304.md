# Agentic AI V4 — Batch 304

Batch 304 externally attests Batch 303 lifecycle finalization receipts. Each attestation binds the receipt ID, digest and generation to the matching lifecycle finalization event, challenge/action lineage, replacement reference, receipt-chain prefix digest, source checkpoint fingerprint, lifecycle audit digest, and signing-key lifecycle state. Attestations form an append-only predecessor chain and are verified against historical signatures and source receipt data.

The service refuses to fabricate attestations when source receipts are absent. It reports missing attestations as recovery-required, invalid signatures or chain bindings as unhealthy, stale key lifecycle as stale until revalidated, and terminal source revocation as decision-blocked. Reconciliation checks source lifecycle health, advances the independent checkpoint before attestation when required, attests receipts, advances the checkpoint again, and audits the resulting chain.

Owner-scoped attest, audit, snapshot, and reconcile APIs are integrated into overall recovery-gate convergence. See `BATCH304_STATUS.md`, `BATCH304_VALIDATION_REPORT.md`, and `ROADMAP_BATCH304.md` for validation scope and remaining work.
