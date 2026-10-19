# Agentic AI V4 — Batch 241

## Purpose

Batch 241 adds a renewal/revocation lifecycle around Batch 240 external attestations, including cross-generation supersession and signed finalization receipts.

## Lifecycle

Renewal: `intent → renewed → superseded → finalized → finalization receipt`.

Revocation: `intent → revoked → finalized → finalization receipt`.

Every phase binds the challenge and lifecycle generation to the active Batch 240 attestation and its Batch 239 source finalization receipt. A finalized revocation is terminal.

## Integrity controls

- Monotonic lifecycle and receipt generations.
- Signed append-only events and historical signature verification.
- Predecessor/replacement binding for renewal.
- Operation-ID idempotency and conflict rejection.
- Receipt-to-finalization binding, receipt-chain continuity, and lifecycle audit digest.
- Signing-key cutoff recording and revalidation.
- Fail-closed source and checkpoint preconditions.

## Recovery

Reconciliation resumes incomplete challenges, advances the independent checkpoint, and re-audits lifecycle and receipt state. A finalized event without its receipt remains `recovery_required`; invalid bindings or terminal-revocation descendants are `unhealthy`.

## API

The owner-authenticated routes are mounted below the Batch 240 external-attestation path at `/lifecycle`: `prepare`, `apply`, `audit`, `snapshot`, and `reconcile`.

## Validation scope

Batch 102 and focused Batch 223–241 regression tests passed (53/53) against the extracted source. Full cumulative `npm test` has not been certified as passing.
