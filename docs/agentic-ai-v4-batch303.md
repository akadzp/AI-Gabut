# Agentic AI V4 — Batch 303

Batch 303 renews or revokes Batch 302 external attestations through a signed, append-only lifecycle. A challenge is prepared only when the Batch 302 attestation audit is current, the source lifecycle and checkpoint are acceptable, and the target attestation is the current chain head. Applying a challenge records the intent, action event, supersession where applicable, finalization event, and finalization receipt. Operation IDs are deterministic so interrupted phases can be resumed without duplicating committed events.

The lifecycle audit verifies signatures, generation continuity, intent/action bindings, active target lineage, predecessor/replacement references, terminal revocation, receipt-to-finalization bindings, receipt predecessor continuity, signing-key cutoff state, and independent checkpoint freshness. An unhealthy ledger or invalid chain fails closed; a terminal revocation yields `decision_blocked`; missing finalization receipts or stale checkpoint state require recovery.

Batch 303 APIs are owner-scoped and are integrated into overall recovery-gate convergence. Empty history does not fabricate events or receipts.

See `BATCH303_STATUS.md`, `BATCH303_VALIDATION_REPORT.md`, and `ROADMAP_BATCH303.md` for validation scope and remaining work.
