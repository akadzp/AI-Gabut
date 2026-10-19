# Agentic AI V4 — Batch 258

## Scope

Batch 258 externally attests Batch 257 lifecycle finalization receipts, preserving receipt-chain continuity, signed attestation history, signing-key cutoff evidence, and independent-checkpoint-aware recovery.

## Attestation lifecycle

- `attestExternalBatch257LifecycleFinalizationReceipts` accepts only a healthy continuity ledger and a complete Batch 257 lifecycle receipt audit.
- Every attestation binds the receipt ID/digest/generation, finalization event ID/digest, challenge/action, target/source attestation and receipt links, intent/action events, replacement attestation, receipt binding digest, source receipt-prefix digest, checkpoint fingerprint, lifecycle audit digest, and source/current signing-key lifecycle binding.
- Attestations are signed append-only events with deterministic operation IDs. Repeated calls reuse an attestation only when the current binding and key lifecycle match; a changed binding produces a new attestation linked to the prior attestation.
- The audit verifies historical signatures, exact receipt/finalization linkage, monotonic attestation generation, predecessor continuity, receipt-prefix digests, binding digests, key-cutoff flags, source audit status, and checkpoint freshness.
- Reconciliation first reconciles Batch 257 lifecycle state, then creates missing or refreshed attestations and reports complete only when every source receipt is attested and the audit is usable or terminally decision-blocked.
- Empty source history remains `not_initialized` and does not fabricate receipts or attestations.

## Checkpoint and API integration

Batch 258 event types are admitted by the signed continuity-ledger validator and receive dedicated schema checks. The independent cross-domain checkpoint snapshot includes Batch 258 events. Overall recovery-gate convergence includes the Batch 258 audit, generation-binding digest, required-state flag, and usability decision.

Owner-scoped routes are registered below `${batch257ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`:

- `POST /attest`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

## Validation boundary

Focused Batch 258 tests, the Batch 256 and Batch 257 regressions, syntax checks, relative-import checks, and archive/extraction integrity checks are run for this release. Full cumulative `npm test` and live HTTP listener startup are not claimed as verified by this batch run.
