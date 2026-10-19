# Agentic AI V4 — Batch 196

## Lifecycle Disposition Checkpoint Separation and Expiry Reconciliation

Batch 196 introduces a dedicated external snapshot checkpoint for marker-recovery journal lifecycle recovery-intent disposition events. The projection contains only the signed `marker_recovery_journal_attestation_lifecycle_recovery_intent_disposition` and `..._disposition_finalization` events from the persistent recovery-receipt ledger. Unrelated receipt events do not advance this checkpoint.

### Dedicated trust domain

- Domain: `cross_domain_recovery_intent_closure_lifecycle_dispositions`
- Environment URL: `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ANCHOR_URL`
- Environment token: `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ANCHOR_TOKEN`
- Strict requirement: `AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ANCHOR=true`

The provider must be independent from the recovery-receipt, marker-recovery-journal, transition, orphan-disposition, and other trust domains. Enrollment is explicit. A configured but unenrolled or stale checkpoint blocks new disposition mutations.

### Commit and recovery behavior

1. A disposition challenge binds the dedicated checkpoint anchor digest, sequence, and freshness snapshot.
2. Before the first disposition event is committed, the challenge and both the recovery-receipt and dedicated disposition checkpoints must still match their prepared bindings.
3. The signed disposition event is persisted in the append-only recovery-receipt ledger, then the shared recovery-receipt checkpoint and dedicated disposition projection are advanced independently.
4. The signed finalization receipt is appended and both checkpoints are verified current before the challenge is finalized with CAS.
5. If a local event committed but the dedicated external CAS failed, retry uses the deterministic operation ID and resumes the same event. Multi-event gaps and rollback are not repaired automatically.

### Challenge-expiry reconciliation

`reconcileMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDispositionChallenge` distinguishes two states:

- Expired with no durable disposition event: CAS-marks the challenge `expired` with an explicit `expired_without_commit` reconciliation record. No disposition event is created.
- Durable disposition event exists: resumes the original challenge's checkpoint/finalization chain even if its short-lived challenge window elapsed after the commit. The persisted event, signatures, bindings, key cutoff, and checkpoints are still verified.

The reconciliation operation is idempotent. It does not create a replacement challenge or duplicate a disposition/finalization receipt.

### Closure decision gate

The independent continuity audit includes the dedicated disposition checkpoint. If it is not current, lifecycle continuity is stale and the closure decision gate cannot report closure complete or evidence usable for a current decision. A dispositioned lifecycle intent remains unusable for current-decision evidence even when its operational handling is fully finalized.

### API

- `GET .../marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/status`
- `GET .../marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/audit`
- `POST .../marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/reconcile`
- `POST .../marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/enrollment/prepare`
- `POST .../marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/enrollment/apply`
- `POST .../marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/challenge/reconcile`

All routes use the authenticated owner. No private key material is included in the source archive.

### Validation

Batch 196 regression tests cover dedicated checkpoint enrollment, expiry without commit, recovery after durable commit and checkpoint failure, closure blocking while the checkpoint is stale, provider-reuse detection, and route wiring. Local storage and external providers remain separate systems rather than a distributed transaction; recovery relies on signed append-only events, deterministic operation IDs, CAS, and checkpoint reconciliation.
