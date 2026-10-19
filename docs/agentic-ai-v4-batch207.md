# Agentic AI V4 — Batch 207

## Scope

Batch 207 adds lifecycle-checkpoint drift monitoring, retained signed drift evidence, revocation-recovery receipt continuity, and cross-generation lifecycle closure revalidation.

## Lifecycle-checkpoint drift

- Drift observations use a distinct `checkpointScope: "lifecycle"` binding so lifecycle-anchor incidents cannot be confused with proof-checkpoint incidents.
- Observations are Ed25519-attested append-only events in the proof-continuity ledger.
- Repeated observations of the same unresolved lifecycle checkpoint fingerprint are idempotent; a later recurrence after a finalized resolution receives a new generation.
- Monitoring never rewrites the lifecycle external anchor.
- Lifecycle drift can be resolved only after the lifecycle checkpoint and proof checkpoint are current. The continuity event is not treated as resolved until its drift-resolution finalization receipt is also present.
- The independent proof-continuity checkpoint anchors the drift observation, continuity attestation, and finalization receipt.

## Revocation-recovery receipt continuity

- A completed revocation automatically creates `proof_continuity_revocation_recovery_receipt_finalized`.
- The signed receipt binds the revoked attestation, revocation event, lifecycle finalization event, lifecycle generation, proof checkpoint, lifecycle checkpoint, and current signing-key lifecycle binding.
- The receipt is excluded from the lifecycle checkpoint's own source projection to avoid a circular checkpoint dependency, but is included in the general proof-continuity ledger and therefore anchored by the independent proof-continuity checkpoint.
- If the receipt is persisted locally and checkpoint advancement fails, retry reuses the existing receipt and reconciles the external checkpoint rather than appending a duplicate.
- Receipt generations form an explicit previous-receipt ID/digest chain. A key-binding change makes the prior receipt stale for current-decision use. A new receipt generation may be issued under the current key and must link to its predecessor; the original revocation remains terminal for its target.

## Cross-generation closure revalidation

- Lifecycle generations advance monotonically across renewal operations, including when a new continuity attestation becomes the target.
- Closure revalidation binds the latest continuity attestation, lifecycle action, finalization, revocation receipt, proof checkpoint, lifecycle checkpoint, proof-continuity checkpoint, and signing-key lifecycle digest.
- `generationBindingDigest` changes when any bound generation or checkpoint evidence changes.
- `generationBindingCurrent` indicates the lifecycle generation binding is current; it does not override a `decision_blocked` result or make a revoked target usable.
- A terminal revocation yields `decision_blocked` when its receipt and checkpoint continuity are current. Missing/stale receipt evidence yields `recovery_required`.

## API

Under `/api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/rollback-recovery/revalidation-lifecycle/recovery-gate/proof/continuity/`:

- `POST lifecycle-drift/monitor`
- `GET lifecycle-drift/audit`
- `POST lifecycle-drift/reconcile`
- `POST revocation-recovery/receipt/finalize`
- `GET lifecycle-closure/revalidate`

## Validation

- Batch 207 focused tests: 4/4 PASS when run individually.
- Targeted regressions: Batch 205 revocation test 1/1 PASS; Batch 206 lifecycle write-failure recovery and revocation tests 2/2 PASS.
- Full cumulative `npm test` and direct HTTP listener startup are not claimed as passed.
- JavaScript syntax, relative import resolution, ZIP integrity, and post-extraction regression tests are validated before delivery.
- No GitHub commit was made.
