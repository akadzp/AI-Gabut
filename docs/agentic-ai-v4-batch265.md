# Agentic AI V4 — Batch 265

Batch 265 adds a signed renewal/revocation lifecycle for Batch 264 external attestations. It uses append-only lifecycle events, challenge-bound operations, deterministic operation IDs, predecessor/replacement linkage, finalization receipts, and independent checkpoint-aware reconciliation.

## Lifecycle events

- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch264_external_attestation_lifecycle_intent`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch264_external_attestation_lifecycle_renewed`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch264_external_attestation_lifecycle_revoked`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch264_external_attestation_lifecycle_superseded`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch264_external_attestation_lifecycle_finalized`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch264_external_attestation_lifecycle_finalization_receipt_finalized`

## Safety and recovery

- Mutations require a current Batch 264 external-attestation audit and a current independent checkpoint when enabled.
- Renewal binds the predecessor attestation and records the replacement; revocation is terminal.
- Challenge confirmation, target digest, ledger snapshot, generation, and signing-key lifecycle binding are rechecked before mutation.
- Finalization receipts bind the finalization event, lifecycle audit digest, checkpoint fingerprint, signing-key binding, and predecessor receipt.
- Reconciliation resumes incomplete challenges and advances checkpoints around lifecycle mutations.
- Audit rejects invalid signatures, malformed phases, duplicate/orphan receipts, predecessor mismatches, and revocation descendants.
- Empty history is read-only and does not fabricate lifecycle evidence.

## API

The owner-scoped routes are mounted under:

`/finalization-receipts/external-attestations/lifecycle`

The endpoints are `POST /prepare`, `POST /apply`, `GET /audit`, `GET /snapshot`, and `POST /reconcile`.

Focused regression coverage does not replace a positive persisted-ledger end-to-end scenario with a verified-current Batch 264 source. See `BATCH265_VALIDATION_REPORT.md` for validation scope and limitations.
