# Agentic AI V4 — Batch 235

## External lifecycle finalization-receipt attestation

Batch 235 adds a signed external attestation chain over Batch 234 lifecycle finalization receipts. Each event binds the source receipt ID/digest/generation, finalized lifecycle event, source and target attestations, source finalization receipt, intent/action events, receipt-chain prefix digest, source checkpoint fingerprint, source lifecycle audit digest, and signing-key lifecycle binding.

### Lifecycle and recovery guarantees

- Attestation events use deterministic operation IDs and an append-only, signed ledger.
- Each event binds a monotonically increasing attestation generation and predecessor ID/digest.
- Audits verify historical signatures, source receipt bindings, prefix digests, predecessor continuity, and key-cutoff state.
- Missing receipt attestations are reported as `recovery_required`; malformed bindings or signatures are `unhealthy`.
- Terminal revocation remains `decision_blocked`; a new attestation does not restore a revoked source.
- Reconciliation recovers missing attestations and advances the already-configured independent finalization-receipt checkpoint through the application layer.
- The overall attestation-receipt convergence audit now includes Batch 235 whenever Batch 234 finalization receipts exist.

### API routes

Base path:

`/api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/rollback-recovery/revalidation-lifecycle/recovery-gate/proof/continuity/finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/finalization-receipt-attestation/lifecycle-finalization-receipt-attestation/lifecycle/finalization-receipts/external-attestations`

- `POST /attest`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

Routes use the application's existing authenticated owner identity. No new provider credentials are bundled.

### Validation scope

Batch-specific regression tests cover empty-history fail-closed behavior, snapshot semantics, API wiring, and route registration. Syntax/import/archive checks are separate from end-to-end renewal/revocation integration; the latter must not be inferred from focused tests alone.
