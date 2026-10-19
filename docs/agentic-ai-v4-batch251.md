# Agentic AI V4 — Batch 251

## Renewal/Revocation Lifecycle for Batch 250 External Attestations

Batch 251 adds a signed, challenge-bound renewal/revocation lifecycle for Batch 250 external attestations. The lifecycle preserves append-only history and binds intent, action, supersession, finalization, and finalization receipt events to the active attestation, source finalization receipt, reason digest, checkpoint fingerprint, and signing-key lifecycle binding.

### Guarantees

- Only a `renew` or `revoke` action is accepted, with explicit confirmation and a bounded challenge TTL.
- The Batch 250 external-attestation source and independent checkpoint must be current before a lifecycle mutation.
- Renewal emits a replacement attestation and a predecessor/supersession binding; terminal revocation blocks descendant lifecycle operations.
- Lifecycle finalization produces a receipt with monotonic generation, predecessor receipt continuity, and a digest over the lifecycle audit and checkpoint binding.
- Stable phase operation IDs support idempotent replay and recovery after interruption.
- Signing-key cutoff is recorded and revalidated; stale or invalid bindings fail closed.
- The independent checkpoint snapshot recognizes Batch 251 events, and the overall recovery gate includes the Batch 251 lifecycle audit.
- Owner-scoped authenticated routes expose `prepare`, `apply`, `audit`, `snapshot`, and `reconcile`.

### Validation policy

Focused Batch 251 tests, syntax/import checks, ZIP integrity, and clean-extraction equivalence must be run against the final extracted archive. Do not claim the full cumulative test suite or a populated-source positive end-to-end lifecycle as passing unless those runs complete and produce a final summary. No GitHub commit is made.
