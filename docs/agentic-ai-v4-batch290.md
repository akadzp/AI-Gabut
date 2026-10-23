# Agentic AI V4 — Batch 290

## Scope

Batch 290 externally attests Batch 289 external-attestation lifecycle finalization receipts. It adds a signed append-only event type:

`proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch289_lifecycle_finalization_receipt_external_attested`

## Receipt-to-attestation binding

Each attestation binds the source receipt ID, digest, and generation; lifecycle finalization event ID and digest; challenge/action; target and source receipt bindings; intent/action event IDs and digests; replacement attestation when applicable; receipt-binding digest; receipt-chain prefix digest; source checkpoint fingerprint; lifecycle audit digest; source/current signing-key lifecycle binding; key-cutoff state; and predecessor attestation ID/digest.

The service rejects an unhealthy source ledger, an incomplete or non-current Batch 289 lifecycle receipt chain, a non-current enabled checkpoint, or an unavailable signing-key lifecycle binding. Existing attestations are reused only when their full current binding and signature key binding still match. Changed bindings append a replacement attestation with a monotonic generation and predecessor reference.

## Recovery and audit

Batch 290 adds attestation, audit, snapshot, and reconciliation service methods; owner-scoped application wrappers; independent-checkpoint inventory inclusion; overall recovery-gate convergence; and HTTP routes beneath the Batch 289 lifecycle route root:

- `POST .../finalization-receipts/external-attestations/attest`
- `GET .../finalization-receipts/external-attestations/audit`
- `GET .../finalization-receipts/external-attestations/snapshot`
- `POST .../finalization-receipts/external-attestations/reconcile`

The audit validates historical signatures, generation order, predecessor continuity, receipt and finalization bindings, receipt-chain prefix digest, checkpoint fingerprint, key lifecycle binding, and missing receipt attestations. Missing attestations or a stale checkpoint require recovery; invalid bindings or signatures are unhealthy; a verified terminal source revocation remains decision-blocked.

## Validation boundary

The Batch 290 tests cover empty-history read-only behavior, API/service/checkpoint/convergence wiring, and malformed-binding schema checks. Focused regression tests and syntax/archive checks are not a substitute for a full cumulative end-to-end run.
