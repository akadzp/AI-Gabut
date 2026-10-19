# Agentic AI V4 — Batch 269

## Scope

Batch 269 adds a signed renewal/revocation lifecycle for Batch 268 external attestations. It is cumulative on Batch 268 and adds lifecycle intent, renewal, revocation, supersession, finalization, and finalization-receipt events.

## Lifecycle guarantees

- A lifecycle challenge is owner-scoped, time-limited, bound to the ledger snapshot, target attestation, receipt, and current signing-key binding.
- Mutations require the Batch 268 external-attestation audit to be `verified_current` and require an enabled independent checkpoint to be current.
- Renewal produces a predecessor-linked replacement and supersession event.
- Revocation is terminal; descendants after a terminal revocation are rejected and the decision gate is blocked.
- Each finalized lifecycle generation has a signed finalization receipt bound to its event chain and previous receipt.
- Operation IDs make phase retries idempotent; mismatched ledger/key/target state is rejected.
- Reconciliation resumes pending challenges and reports incomplete checkpoint advancement as `recovery_required`.
- Batch 269 events are included in the append-only ledger schema validation and independent checkpoint snapshot.

## API

The owner-authenticated lifecycle routes are mounted below:

`/finalization-receipts/external-attestations/lifecycle`

Routes: `POST /prepare`, `POST /apply`, `GET /audit`, `GET /snapshot`, and `POST /reconcile`.

## Validation scope

Focused regression tests, syntax validation, import resolution, and archive integrity are reported in `BATCH269_VALIDATION_REPORT.md`. The full cumulative `npm test` suite and full positive end-to-end renewal/revocation against a constructed current Batch 268 attestation are not claimed as passed unless a final complete run is recorded.
