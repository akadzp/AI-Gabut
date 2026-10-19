# Agentic AI V4 — Batch 261

Batch 261 adds a lifecycle for Batch 260 external attestations. Operations are bound to the current source attestation, source finalization receipt, signing-key lifecycle binding, and independent checkpoint. Renewal creates a replacement and supersedes the predecessor; revocation is terminal. Each successful operation requires a finalization receipt, and reconciliation repairs interrupted phases without silently declaring a stale checkpoint current.

Lifecycle API methods: prepare, apply, audit, snapshot, and reconcile. The HTTP routes are owner-scoped under `/finalization-receipts/external-attestations/lifecycle`.
