# Agentic AI V4 — Batch 297

Batch 297 adds a signed renewal/revocation lifecycle for Batch 296 external attestations. It records deterministic, owner-scoped lifecycle intents; renewal or terminal revocation; supersession; finalization; and a bound finalization receipt. Lifecycle bindings include challenge and generation lineage, target attestation and source receipt IDs/digests, reason digest, signing-key lifecycle binding, key-cutoff revalidation, phase-event linkage, predecessor/replacement attestation linkage, checkpoint fingerprint, and receipt-chain continuity.

The service verifies Batch 296 attestation state and Batch 295 lifecycle-receipt attestation before mutation, rejects non-current or unhealthy source state, preserves append-only history, rejects replay with conflicting bindings, and treats revocation as terminal. Recovery resumes incomplete phases and receipt creation without fabricating source attestations.

Batch 297 is registered in the cumulative ledger allowlist and schema validation, independent checkpoint event inventory, application recovery-gate convergence, generation-binding digest, final usability gate, and owner-scoped HTTP routes. The source tree remains cumulative. No GitHub commit is performed.
