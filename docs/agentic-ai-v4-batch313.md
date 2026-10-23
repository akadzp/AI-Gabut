# Agentic AI V4 — Batch 313

Batch 313 provides a signed renewal/revocation lifecycle for Batch 312 external attestations. It validates the active source attestation and its finalization receipt, binds every lifecycle phase to a generation and signing-key lifecycle digest, enforces predecessor/replacement continuity, finalizes a receipt for each completed operation, and blocks descendants after terminal revocation.

Recovery reconciles pending lifecycle phases and independent checkpoint state before the overall recovery gate can consider the chain current. Owner-scoped application methods and HTTP routes expose prepare, apply, audit, snapshot, and reconcile operations.

Focused validation passed for 46 selected regression tests, including 6 Batch 313 tests. Full cumulative `npm test`, positive end-to-end source provisioning, crash-injection at all boundaries, and live HTTP startup remain unverified. No GitHub commit was made.
