# Agentic AI V4 — Batch 253

## Renewal/Revocation Lifecycle for Batch 252 External Attestations

Batch 253 adds a signed, append-only renewal/revocation lifecycle for Batch 252 external attestations. Each lifecycle operation binds the current Batch 252 attestation ID, digest, and generation to the source finalization receipt, reason digest, signing-key lifecycle binding, checkpoint fingerprint, challenge, intent/action/supersession/finalization events, and finalization receipt.

Renewal follows `intent → renewed → superseded → finalized → finalization receipt`. Revocation follows `intent → revoked → finalized → finalization receipt` and is terminal. Deterministic operation IDs protect retries; the audit verifies signatures, phase consistency, predecessor/replacement links, receipt-chain continuity, generation monotonicity, key-cutoff state, and checkpoint currentness. Missing receipts or interrupted operations remain `recovery_required`; invalid bindings are `unhealthy`; terminal revocation is `decision_blocked`.

The service exposes owner-scoped prepare/apply/audit/snapshot/reconcile operations. Application wrappers advance independent checkpoints after lifecycle mutations and reconcile pending challenges without inventing source attestations.

## Validation scope

Batch 253 focused tests cover empty-history non-mutation, fail-closed behavior when the Batch 252 source attestation is not current, lifecycle API registration, checkpoint snapshot inclusion, overall recovery-gate convergence, and owner-scoped HTTP route registration. Full cumulative tests and live HTTP startup must be reported separately when not completed.
