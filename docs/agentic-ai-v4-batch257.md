# Agentic AI V4 — Batch 257

## Scope

Batch 257 adds a signed renewal/revocation lifecycle for Batch 256 external attestations, including cross-generation supersession, finalization receipts, and independent-checkpoint-aware recovery.

## Lifecycle

- `prepareBatch257ExternalAttestationLifecycle` accepts only `renew` or `revoke`, validates the reason and TTL, and requires a current Batch 256 external-attestation audit plus current checkpoint state.
- `applyBatch257ExternalAttestationLifecycle` validates the owner-scoped challenge and explicit confirmation phrase, checks that the ledger has not changed since preparation, and resumes idempotently by phase operation ID.
- Renewal appends renewed, superseded, finalized, and finalization-receipt events. Revocation appends revoked, finalized, and finalization-receipt events.
- Terminal revocation prevents later descendant lifecycle generations.
- Audit checks event signatures, phase cardinality, challenge/generation binding, target and replacement links, receipt bindings, source-receipt existence, predecessor receipt continuity, key cutoff, and checkpoint freshness.
- Reconciliation resumes pending challenges and reports completion only when no pending phase or missing receipt remains.

## Event and checkpoint integration

Batch 257 event types are admitted by the append-only continuity ledger validator and receive dedicated schema validation. The independent cross-domain checkpoint snapshot includes Batch 257 lifecycle and receipt events. Application-level recovery-gate convergence includes the Batch 257 audit, digest, and decision usability.

## API

Owner-scoped endpoints are registered below `${batch256ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`:

- `POST /prepare`
- `POST /apply`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

## Validation boundary

The Batch 257, Batch 256, Batch 255, Batch 254, Batch 253, Batch 252, Batch 251, Batch 250, Batch 102 entrypoint/dependency, and artifact-focused regression tests are run for this release. Full cumulative `npm test` and a live HTTP listener startup are not claimed as verified by this batch run.
