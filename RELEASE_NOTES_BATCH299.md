# Release Notes — Agentic AI V4 Batch 299

## Summary
Batch 299 adds renewal and terminal-revocation lifecycle controls for Batch 298 external attestations.

## Changes
- Added signed append-only lifecycle events for intent, renewal, revocation, supersession, finalization, and finalization receipts.
- Required the Batch 298 source attestation audit to be `verified_current` before mutation.
- Bound lifecycle phases to a challenge, target attestation, source finalization receipt, generation, reason digest, and signing-key lifecycle state.
- Added deterministic operation IDs and resumable phases for interruption recovery.
- Validated predecessor/replacement continuity, receipt binding, finalization linkage, and terminal-revocation descendants.
- Added independent checkpoint inventory, recovery-gate convergence, application APIs, and owner-scoped HTTP routes.
- Added five focused regression tests for no-op behavior, input validation, source gating, integration wiring, and event-schema binding.

## Compatibility and safety
- Existing Batch 297 and Batch 298 interfaces remain available.
- Invalid actions, malformed reasons, invalid TTLs, unhealthy ledgers, stale source attestations, and non-current checkpoints are rejected before unsafe lifecycle mutation.
- A finalized revocation remains terminal; no reactivation action is supported.

## Validation
See `BATCH299_VALIDATION_REPORT.md` for exact test counts, syntax checks, archive integrity, and known untested integration paths.

No GitHub commit was made.
