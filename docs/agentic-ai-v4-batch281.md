# Agentic AI V4 — Batch 281

## Scope
Batch 281 adds a signed renewal/revocation lifecycle for Batch 280 external attestations. It preserves the cumulative source tree, requires a current source-attestation audit and independent checkpoint, binds each operation to a challenge and signing-key lifecycle digest, and records append-only lifecycle and finalization-receipt events.

## Lifecycle
- `prepare`: validates action, reason, active source attestation, receipt binding, key binding, checkpoint freshness, and ledger head.
- `apply`: persists intent, renewal/revocation, supersession where applicable, finalization, and a chained finalization receipt using deterministic operation IDs.
- `audit`: verifies phase order, signatures, predecessor/successor links, receipt continuity, key-cutoff state, and checkpoint freshness.
- `resume` / `reconcile`: recovers incomplete phases without fabricating missing source evidence and advances independent checkpoints.

## Safety behavior
- Invalid source or signature: `unhealthy`.
- Missing receipt/checkpoint continuity or pending phase: `recovery_required`.
- Unrevalidated signing-key cutoff: `stale`.
- Verified terminal revocation: `decision_blocked`.
- Empty history is read-only and `not_initialized`.

## HTTP
Owner-scoped routes are mounted under the Batch 280 external-attestation root plus `/lifecycle`, with `prepare`, `apply`, `audit`, `snapshot`, and `reconcile` endpoints.

## Validation limits
Focused regression tests, syntax checks, import/API checks, and archive extraction checks are run for the release. Full cumulative test-suite completion and a positive end-to-end flow are reported separately and are not assumed to pass without execution.
