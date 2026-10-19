# Agentic AI V4 — Batch 247

## Purpose

Batch 247 adds a signed renewal/revocation lifecycle for Batch 246 external attestations. It preserves the cumulative Batch 246 source and adds cross-generation supersession, lifecycle finalization receipts, replay-safe recovery, independent-checkpoint reconciliation, and owner-scoped API access.

## Lifecycle integrity

- Only a current, verified Batch 246 external attestation can be the source target for a new lifecycle operation.
- Supported actions are `renew` and `revoke`; unsupported activation or resurrection actions fail closed.
- Renewal follows `intent → renewed → superseded → finalized → finalization receipt`.
- Revocation follows `intent → revoked → finalized → finalization receipt` and remains terminal.
- Every event binds the challenge, monotonically increasing generation, target attestation, source finalization receipt, reason digest, and signing-key lifecycle binding.
- The replacement chain binds predecessor/replacement IDs and digests. A finalized terminal revocation blocks later descendants.
- Finalization receipts bind the finalization event, action and intent events, receipt-chain predecessor, lifecycle audit digest, signing-key binding, and checkpoint fingerprint.
- Missing receipts or stale independent checkpoints require recovery; invalid signatures, bindings, or chain links are unhealthy.
- Deterministic operation IDs make phase replay idempotent. Reconciliation resumes pending challenges, completes missing receipts only from verified finalization events, advances the checkpoint, and re-audits.

## API

Owner-scoped authenticated endpoints are added beneath `/finalization-receipts/external-attestations/lifecycle`:

- `POST /prepare`
- `POST /apply`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

## Validation scope

Focused tests cover empty-history fail-closed behavior, source-attestation prerequisites, snapshot domain, checkpoint inclusion, recovery-gate convergence, and route registration. The full cumulative suite and positive end-to-end renewal/revocation flow are not claimed as passing unless the complete run produces a successful final summary.

## GitHub

No commit performed.
