# Release Notes — Agentic AI V4 Batch 301

Batch 301 introduces lifecycle renewal and terminal revocation for Batch 300 external attestations. Each operation is challenge-bound and uses deterministic phase operation IDs to support idempotent recovery. Renewal binds predecessor and replacement attestations; revocation blocks subsequent descendants. A finalization receipt is required for each completed lifecycle generation, with signing-key lifecycle, checkpoint fingerprint, receipt digest, and predecessor receipt binding. Application reconciliation advances the independent checkpoint and the overall recovery-gate audit now includes Batch 301 usability.

No GitHub commit was made.
