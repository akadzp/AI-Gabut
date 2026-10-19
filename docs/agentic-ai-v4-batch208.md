# Agentic AI V4 — Batch 208

## Lifecycle drift-evidence external checkpoint

Batch 208 introduces the independent external trust domain `cross_domain_recovery_gate_proof_continuity_lifecycle_drift_evidence`.

Its deterministic source projection contains lifecycle-scope drift observations, continuity attestations that resolve those observations, drift-resolution finalization receipts, revocation recovery receipts, and revocation-receipt lifecycle events. The projection intentionally excludes unrelated proof-scope drift and unrelated continuity events.

The checkpoint is independently configured and is checked for provider/endpoint reuse against all registered recovery SLO anchor domains. Strict mode blocks lifecycle evidence use until enrollment is complete and the checkpoint is current. Advancement is restricted to a single provable projected event; multi-event gaps, rollback, provider reuse, and policy drift fail closed.

## Revocation-receipt lifecycle

A signed, append-only lifecycle ledger now manages revocation recovery receipt generations through `renew` and `revoke` challenges. Challenges bind the target receipt ID/digest, receipt generation, revocation/finalization binding, ledger head/count/snapshot, checkpoint fingerprints, current key binding, and expiry.

Renewal creates a new revocation receipt generation, links it to its predecessor by receipt ID/digest, and records lifecycle renewal, supersession, and finalization events. Revocation marks the selected receipt generation withdrawn without deleting the original revocation evidence or making the revoked continuity attestation usable again.

Each apply call advances at most one ledger event. Retry uses deterministic operation IDs and reuses any receipt already created for the challenge. Concurrent challenges created from the same generation are rejected after the first operation changes the ledger snapshot. Signing-key cutoff is retained in the lifecycle evidence; it cannot be erased by a later signature or receipt renewal.

## Recovery and decision gate

The application advances the general proof-continuity checkpoint and the lifecycle drift-evidence checkpoint after each projected event. The continuity-checkpoint reconciliation path also advances the lifecycle drift-evidence checkpoint after each drift-resolution receipt, avoiding a projected multi-event jump.

Closure revalidation binds the receipt-lifecycle generation digest and the current lifecycle drift-evidence checkpoint. A current receipt lifecycle does not override a terminal revocation of the underlying continuity attestation. A withdrawn receipt generation or a non-current checkpoint keeps the recovery gate blocked.

## API

Under `/api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/rollback-recovery/revalidation-lifecycle/recovery-gate/proof/continuity/`:

- `GET lifecycle-drift-evidence-checkpoint/status`
- `GET lifecycle-drift-evidence-checkpoint/audit`
- `POST lifecycle-drift-evidence-checkpoint/enrollment/prepare`
- `POST lifecycle-drift-evidence-checkpoint/enrollment/apply`
- `POST lifecycle-drift-evidence-checkpoint/reconcile`
- `POST revocation-recovery/receipt/lifecycle/prepare`
- `POST revocation-recovery/receipt/lifecycle/apply`
- `GET revocation-recovery/receipt/lifecycle/audit`

## Configuration

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_DRIFT_EVIDENCE_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_DRIFT_EVIDENCE_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_DRIFT_EVIDENCE_ANCHOR=true
```

The provider must be independent of every other registered trust domain. Credentials and private keys are not included in the source archive.

## Validation

- Batch 208 focused regression tests: 8/8 PASS when executed individually, including interruption between continuity attestation and drift receipt finalization, plus revocation-receipt lifecycle write-failure recovery.
- Batch 207 focused regression tests: 4/4 PASS when executed individually.
- Batch 206 focused regression tests: 6/6 PASS when executed individually.
- Full cumulative `npm test` is not claimed as passed.
- Direct HTTP listener startup is not claimed as passed; the validation environment does not have `express` installed.
- JavaScript syntax, relative import resolution, archive integrity, and post-extraction regression tests are checked before delivery.
- No GitHub commit was made.
