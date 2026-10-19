# Agentic AI V4 — Batch 243

## Purpose

Batch 243 adds a signed renewal/revocation lifecycle for Batch 242 external attestations. It adds cross-generation supersession, per-finalization receipts, signing-key cutoff tracking, checkpoint-aware replay, and recovery-gate convergence.

## Lifecycle

- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch242_external_attestation_lifecycle_intent`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch242_external_attestation_lifecycle_renewed`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch242_external_attestation_lifecycle_revoked`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch242_external_attestation_lifecycle_superseded`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch242_external_attestation_lifecycle_finalized`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch242_external_attestation_lifecycle_finalization_receipt_finalized`

Renewal follows `intent → renewed → superseded → finalized → receipt`. Revocation follows `intent → revoked → finalized → receipt` and remains terminal. Receipt generations require a valid predecessor, and every receipt binds the finalization, action, source receipt, key lifecycle, checkpoint fingerprint, and lifecycle audit digest.

## Integrity and recovery

- Batch 242 external attestation must be `verified_current` before lifecycle mutation.
- Operation IDs are deterministic; replays with conflicting ledger state are rejected.
- Every lifecycle event and receipt is signature-verified and checked against its stable binding.
- Missing finalization receipts or stale checkpoints produce `recovery_required`; broken bindings, orphan phases, invalid signatures, or invalid predecessor links produce `unhealthy`.
- Terminal revocation remains `decision_blocked`; no renewal descendant is accepted.
- Batch 243 events are included in the independent external-attestation checkpoint snapshot and overall recovery-gate convergence.

## API

Routes are owner-scoped and authenticated beneath the Batch 242 external-attestation root at `/finalization-receipts/external-attestations/lifecycle`:

- `POST /prepare`
- `POST /apply`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

## Validation scope

Focused regression validation covers Batch 102 and Batches 223–243: 57/57 tests pass against the extracted source. All 335 JavaScript/MJS/CJS files pass `node --check`, and the Batch 102 import test reports no missing relative imports. The complete cumulative `npm test` suite is not claimed as passed unless it completes with a final passing summary.

## GitHub

No commit performed.
