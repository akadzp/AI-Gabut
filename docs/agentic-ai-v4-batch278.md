# Agentic AI V4 Batch 278 — External Attestation

Batch 278 attests Batch 277 lifecycle finalization receipts and integrates those attestations into independent checkpoint recovery and the global recovery gate.

## Lifecycle

`Batch 277 source receipt audit → pre-attestation checkpoint advancement → external attestation → checkpoint advancement → final audit`

The attestation ledger is append-only. Each event includes a stable binding to the source finalization receipt, lifecycle finalization event, source receipt-chain prefix, source checkpoint, lifecycle audit, signing-key lifecycle, key-cutoff state, and previous attestation when present.

## Status behavior

- `not_initialized`: no source receipts or attestations exist and the source is not otherwise blocked.
- `verified_current`: receipt chain, attestations, signatures, key bindings, and checkpoint satisfy current-decision requirements.
- `recovery_required`: receipts lack attestations, the source audit requires recovery, or the independent checkpoint is not current.
- `stale`: signing-key cutoff requires revalidation or the source audit is stale.
- `unhealthy`: invalid signature, binding, or receipt-chain integrity.
- `decision_blocked`: source lifecycle has a verified terminal revocation.

## HTTP routes

The owner-scoped routes are mounted under the Batch 277 external-attestation lifecycle root plus `/finalization-receipts/external-attestations`, with `attest`, `audit`, `snapshot`, and `reconcile` operations.

## Validation boundary

The Batch 278 focused regression tests and syntax/archive checks are reported in `BATCH278_VALIDATION_REPORT.md`. They do not imply that the entire cumulative test suite or a complete positive end-to-end lifecycle chain has passed.
