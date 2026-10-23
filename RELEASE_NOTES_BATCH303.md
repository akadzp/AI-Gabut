# Release Notes — Agentic AI V4 Batch 303

Batch 303 adds a signed renewal/revocation lifecycle for Batch 302 external attestations. Lifecycle operations are bound to the active attestation, its source finalization receipt, challenge/action data, signing-key lifecycle state, checkpoint state, and predecessor/replacement lineage. Successful operations finalize with an append-only receipt chain; terminal revocation blocks further renewal. Recovery reconciles interrupted phases and missing finalization receipts, while checkpoint state and Batch 303 usability feed the overall recovery-gate convergence.

Owner-scoped prepare, apply, audit, snapshot, and reconcile routes are included. Empty source history remains read-only and does not fabricate lifecycle events or receipts.

No GitHub commit was made.
