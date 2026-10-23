# Agentic AI V4 — Batch 323 Release Notes

## Added

- Renewal and terminal revocation lifecycle events for Batch 322 external attestations.
- Canonical lifecycle bindings for challenge/action/generation, target attestation, source Batch 321 finalization receipt, reason digest, signing-key lifecycle state, intent/action events, predecessor/replacement references, and revocation reason.
- Signed intent, renewal/revocation, supersession, finalization, and lifecycle finalization receipt events.
- Receipt-chain continuity and predecessor validation across lifecycle generations.
- Deterministic operation IDs, challenge expiry/confirmation checks, idempotent phase recovery, and key-cutoff revalidation.
- Independent checkpoint recovery before mutation and after lifecycle phase writes.
- Owner-scoped application methods and HTTP routes for prepare/apply/audit/snapshot/reconcile.
- Overall recovery-gate convergence and checkpoint event inventory integration.
- Six focused Batch 323 regression tests. The existing Batch 322 event-whitelist test was updated to account for the newly registered Batch 323 event types.

## Safety behavior

- Lifecycle mutation is rejected unless the Batch 322 external-attestation source is `verified_current` and the required checkpoint is usable.
- No lifecycle receipt is fabricated when the source attestation or its Batch 321 finalization receipt is missing.
- Invalid challenges, binding mismatches, broken predecessor chains, invalid signatures, and unhealthy source ledgers fail closed.
- Terminal revocation remains decision-blocking; the lifecycle cannot reactivate a revoked target.
- Missing receipt/checkpoint phases remain recoverable rather than being reported as current.

## Validation boundary

Selected regression tests and syntax/archive checks passed. Full cumulative `npm test`, fully provisioned positive end-to-end lifecycle flow, live HTTP listener startup, and phase-boundary crash injection are not claimed as passing. See `BATCH323_VALIDATION_REPORT.md`.
