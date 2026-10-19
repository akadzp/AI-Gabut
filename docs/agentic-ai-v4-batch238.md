# Agentic AI V4 — Batch 238

## Scope

Batch 238 adds signed external attestations for Batch 237 lifecycle finalization receipts. It binds each attestation to the receipt ID/digest/generation, lifecycle finalization event, action and target/source evidence, receipt-binding digest, prefix-chain digest, checkpoint fingerprint, and signing-key lifecycle binding.

## Integrity and recovery

- Attestation events form a signed append-only predecessor chain with monotonic attestation generations.
- Each attestation must reference an existing Batch 237 receipt and reproduce the receipt-prefix digest.
- Historical signatures and binding digests are checked during audit.
- Missing attestations or stale independent checkpoint state fail closed as `recovery_required`.
- Invalid signatures or chain bindings yield `unhealthy`.
- Terminal revocation remains `decision_blocked`; external attestation cannot revive a revoked target.
- Deterministic operation IDs make retries idempotent. Key-binding changes cause a new attestation linked to the prior attestation, preserving historical continuity.

## API

Under the Batch 237 finalization-receipt route, Batch 238 adds:

- `POST /external-attestations/attest`
- `GET /external-attestations/audit`
- `GET /external-attestations/snapshot`
- `POST /external-attestations/reconcile`

Application reconciliation advances the existing independent checkpoint before attestation and again after new attestation events are persisted. The checkpoint snapshot includes Batch 237 receipts and Batch 238 attestation events.

## Validation

Validation includes syntax checks, relative-import resolution, focused Batch 238 regression tests, selected prior-batch regressions, and ZIP extraction/hash integrity checks. Full cumulative `npm test` and full lifecycle end-to-end coverage must be reported separately if not completed.
