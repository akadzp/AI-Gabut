# Agentic AI V4 — Batch 305

Batch 305 adds a signed renewal/revocation lifecycle for Batch 304 external attestations. The lifecycle is append-only and includes intent, renewed/revoked action, supersession, finalization, and finalization-receipt events. Each phase binds the target attestation and source receipt, challenge/action lineage, reason digest, signing-key lifecycle state, checkpoint fingerprint, and predecessor/replacement digests.

Renewal uses a predecessor–replacement chain. Finalized revocation is terminal and blocks subsequent renewal. Deterministic operation IDs support idempotent replay and phase-by-phase recovery. Finalization receipts are chained by generation and audited against lifecycle events, signatures, key-cutoff state, and independent checkpoint state.

Owner-scoped prepare, apply, audit, snapshot, and reconcile APIs are integrated into overall recovery-gate convergence. Empty history remains read-only and does not fabricate lifecycle events or receipts. Source Batch 304 attestation must be verified-current before a new mutation challenge can be prepared.

See `BATCH305_STATUS.md`, `BATCH305_VALIDATION_REPORT.md`, and `ROADMAP_BATCH305.md` for validation scope and remaining work.
