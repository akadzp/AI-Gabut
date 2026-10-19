# Agentic AI V4 — Batch 197

## Disposition-Checkpoint Marker Recovery, External-Anchor Rollback Recovery, and Lifecycle Closure Receipt Revalidation

Batch 197 extends exact-anchor marker recovery to the dedicated lifecycle-disposition checkpoint. Recovery intents and finalization receipts are stored in the externally anchored recovery-receipt ledger. The recovery flow only repairs a marker when the remote anchor proves one-step continuity; it does not overwrite a suspected rollback or fabricate missing anchor history.

### Marker recovery

- Added `lifecycle_disposition` as a supported checkpoint recovery target.
- Preflight requires the status-transition and orphan-disposition counterpart checkpoints to be current.
- The original anchor sequence, source digest/count, previous-anchor digest, policy binding, and recovery-intent digest are persisted in a signed recovery intent.
- Marker recovery succeeds only when the external anchor and source snapshot match the persistent intent and the marker is either already current or exactly one anchor behind.
- Finalization receipts are externally anchored and the recovery-receipt checkpoint is revalidated after recovery.

### Rollback recovery case

Added owner-scoped, challenge-bound rollback incident handling for the lifecycle-disposition checkpoint. It supports `quarantine` and `mark_unrecoverable`, requires a reason and explicit confirmation, and binds the checkpoint fingerprint, marker/anchor sequence and digest, continuity audit, recovery-receipt checkpoint, and signing-key lifecycle. The signed incident event and finalization receipt are mirrored into the recovery-receipt ledger and advance its external checkpoint.

The rollback workflow is deliberately non-destructive: it does not mutate the external anchor or repair a rollback automatically. A rollback remains unhealthy and unusable for current decisions until a separate, verifiable checkpoint recovery restores currentness. Retry after a persisted event reuses the same operation IDs and receipt records.

### Closure receipt revalidation

The read-only rollback audit verifies challenge/event/finalization bindings, Ed25519 attestations, external recovery-receipt ledger links, duplicate detection, key-cutoff metadata, and current checkpoint state. Closure audit includes these findings and remains fail-closed on active rollback, pending receipt links, invalid signatures, or stale evidence. A disposition records incident handling; it does not itself make evidence usable.

### API

- `GET .../recovery-intent-disposition/checkpoint/recovery/inspect`
- `POST .../recovery-intent-disposition/checkpoint/recovery`
- `GET .../recovery-intent-disposition/checkpoint/rollback-recovery/inspect`
- `GET .../recovery-intent-disposition/checkpoint/rollback-recovery/audit`
- `POST .../recovery-intent-disposition/checkpoint/rollback-recovery/prepare`
- `POST .../recovery-intent-disposition/checkpoint/rollback-recovery/apply`

All routes are authenticated and owner-scoped. No private key material is included in the source archive.

### Validation

Batch 197 regression tests cover exact-anchor marker recovery, rollback incident recording without anchor mutation, stale-fingerprint rejection, tampered finalization-receipt detection, and route wiring. Batch 196 regression tests were rerun to detect regressions. External storage and local storage remain separate systems rather than a distributed transaction; signed append-only receipts, deterministic operation IDs, CAS, and reconciliation are used for crash recovery. HTTP listener startup remains unverified if the validation environment does not provide `express`.
