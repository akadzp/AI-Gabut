# Agentic AI V4 — Batch 249

## Scope

Batch 249 adds a signed, append-only renewal/revocation lifecycle for Batch 248 external attestations. The lifecycle binds each challenge to the active Batch 248 attestation and its Batch 247 lifecycle finalization receipt, preserves cross-generation supersession, emits lifecycle finalization receipts, and integrates replay-safe recovery with the independent checkpoint and overall recovery-gate convergence.

## Integrity and recovery rules

- Only `renew` and `revoke` are permitted lifecycle actions.
- A current, healthy Batch 248 external-attestation chain and current independent checkpoint are required before lifecycle mutation.
- Intent, renewal/revocation, supersession, finalization, and finalization receipt events are signed and append-only.
- Generation and predecessor bindings are monotonic; operation IDs are deterministic per challenge and phase.
- Terminal revocation is decision-blocking and cannot be reversed by a descendant lifecycle event.
- Missing finalization receipts and stale checkpoints require recovery; invalid signatures, orphan phases, broken bindings, and invalid descendants fail closed.
- Signing-key cutoff and revalidation state are bound into lifecycle events and receipts.

## API

Authenticated owner-scoped routes are mounted below `/finalization-receipts/external-attestations/lifecycle`: `POST /prepare`, `POST /apply`, `GET /audit`, `GET /snapshot`, and `POST /reconcile`.

## Validation policy

The dedicated regression tests verify empty-history behavior, rejection without a current Batch 248 source, event-schema and application wiring, independent checkpoint snapshot coverage, and route registration. Full cumulative `npm test` and positive end-to-end lifecycle execution must not be claimed unless those runs complete successfully. No GitHub commit is made.
