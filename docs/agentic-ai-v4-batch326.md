# Agentic AI V4 — Batch 326

Batch 326 externally attests Batch 325 lifecycle finalization receipts. Each attestation binds the source receipt and its finalization event, source lifecycle audit, receipt-chain prefix, source checkpoint fingerprint, source and current signing-key lifecycle binding, key-cutoff state, attestation generation, and predecessor attestation ID/digest.

The service rejects unhealthy or non-current source lifecycle receipt chains, validates receipt/finalization bindings, reuses an attestation only when its canonical binding remains identical, and records replacement attestations when a binding changes. Audit validates signatures, receipt coverage, predecessor continuity, key-cutoff revalidation, terminal revocation state, and independent checkpoint usability. Reconciliation first recovers the Batch 325 lifecycle, advances checkpoints before attestation when required, attests eligible receipts, advances checkpoints again, and performs a final audit.

Owner-scoped application methods and HTTP endpoints are provided for attest, audit, snapshot, and reconcile under the Batch 325 external-attestation lifecycle root. Batch 326 is included in the ledger schema allowlist, independent checkpoint inventory, and overall recovery-gate convergence.

Regression coverage verifies empty-history safety, absence of fabricated source receipts, schema and chain-binding wiring, checkpoint inventory, API/HTTP wiring, and global convergence. Full end-to-end provisioning and cumulative-suite limitations are documented in `BATCH326_VALIDATION_REPORT.md`.
