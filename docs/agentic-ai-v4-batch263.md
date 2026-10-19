# Agentic AI V4 — Batch 263

## Scope

Batch 263 adds a signed renewal/revocation lifecycle for Batch 262 external attestations, including cross-generation supersession, finalization receipts, signing-key cutoff handling, replay-safe operations, and checkpoint-aware recovery.

## Lifecycle

`Intent → Renewed → Superseded → Finalized → Finalization Receipt`

Revocation follows `Intent → Revoked → Finalized → Finalization Receipt` and is terminal. A revoked attestation cannot be reactivated through this lifecycle.

## Integrity controls

- Owner-scoped challenge with bounded TTL and explicit confirmation phrase.
- Deterministic operation IDs and append-only signed ledger events.
- Canonical binding digest covering target, source receipt, generation, key lifecycle, intent/action events, predecessor, replacement, and revocation reason.
- Receipt chain with predecessor ID/digest and lifecycle audit digest.
- Source Batch 262 attestation and independent checkpoint must be current before mutation.
- Recovery distinguishes `verified_current`, `recovery_required`, `stale`, `unhealthy`, and `decision_blocked`.

## API

Base route: `/.../finalization-receipts/external-attestations/lifecycle`

Endpoints: `POST /prepare`, `POST /apply`, `GET /audit`, `GET /snapshot`, `POST /reconcile`.

## Validation

See `BATCH263_VALIDATION_REPORT.md`. Regression tests are focused; the full cumulative suite and live HTTP listener startup are not claimed as verified.
