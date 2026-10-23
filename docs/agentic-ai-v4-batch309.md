# Agentic AI V4 — Batch 309

## Purpose

Batch 309 adds a renewal/revocation lifecycle for Batch 308 external attestations. The lifecycle is owner-scoped and requires a verified-current Batch 308 source attestation, an acceptable independent checkpoint state, and a current signing-key lifecycle binding before mutation.

## Lifecycle events

- `BATCH309_INTENT_EVENT`
- `BATCH309_RENEWED_EVENT`
- `BATCH309_REVOKED_EVENT`
- `BATCH309_SUPERSEDED_EVENT`
- `BATCH309_FINALIZED_EVENT`
- `BATCH309_RECEIPT_EVENT`

The renewal flow records intent, replacement attestation, predecessor supersession, finalization, and a finalization receipt. Revocation is terminal and preserves the append-only audit trail. Re-activation is not supported.

## Integrity and recovery

Lifecycle bindings include challenge/action, generation, target attestation, source finalization receipt, reason digest, signing-key lifecycle binding, predecessor/replacement links, event digests, receipt binding, and checkpoint fingerprints. Deterministic phase operation IDs support idempotent resumption. Invalid signatures, conflicting phases, invalid predecessor links, or invalid receipt bindings fail closed.

The independent checkpoint inventory includes Batch 309 events. Overall recovery-gate convergence includes the Batch 309 audit and its generation-binding digest. Reconciliation recovers pending phases and advances checkpoints around lifecycle mutations.

## HTTP API

Base path: `/api/recovery-gate/batch308-external-lifecycle-finalization-receipts/external-attestations/lifecycle` (root is defined in `apps/agentic/backend/server.js`).

- `POST /prepare`
- `POST /apply`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

Routes use the authenticated owner from the request context. Applying a prepared challenge requires the exact confirmation phrase returned by preparation.

## Validation scope

Batch 309 regression tests cover empty-history behavior, invalid action/reason/TTL rejection, the verified-current source gate, service/checkpoint/convergence/route wiring, and ledger schema bindings. The full cumulative `npm test` suite and a positive end-to-end renewal/revocation against a fully provisioned current source chain remain unverified in this environment.
