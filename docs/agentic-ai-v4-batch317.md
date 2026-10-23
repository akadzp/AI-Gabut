# Agentic AI V4 — Batch 317

Batch 317 introduces renewal and terminal revocation for Batch 316 external attestations.

## Invariants
- A lifecycle challenge is owner-scoped, digest-protected, time-bounded, and bound to the current ledger head and target attestation.
- Only `renew` and `revoke` are accepted; this lifecycle cannot reactivate a revoked attestation.
- Renewal creates a replacement event linked to the prior attestation and a supersession event.
- Every finalized lifecycle generation must have exactly one finalization receipt linked to its finalization event.
- Receipt bindings include the source Batch 315 finalization receipt, Batch 316 target attestation, intent/action events, lifecycle audit digest, checkpoint fingerprint, signing-key binding, and predecessor receipt.
- Invalid signatures, broken generation continuity, orphaned phases, duplicate/missing receipts, stale key bindings, or non-current checkpoints prevent current-decision usability.
- Reconciliation resumes persisted phases idempotently and advances the independent checkpoint after mutations.

## API
The owner-scoped lifecycle routes are mounted below:
`/finalization-receipts/external-attestations/lifecycle/finalization-receipts/external-attestations/lifecycle`

Routes: `POST /prepare`, `POST /apply`, `GET /audit`, `GET /snapshot`, `POST /reconcile`.

## Validation boundary
Focused regression suites, syntax checks, import/API checks, and archive integrity checks are run. The full cumulative `npm test` suite and a fully provisioned positive end-to-end chain are not claimed as complete in this batch.
