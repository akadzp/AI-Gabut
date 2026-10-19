# Agentic AI V4 — Batch 188

## External closure and disposition checkpoints

Batch 188 adds two independent external snapshot trust domains for the recovery-intent status-transition ledger and orphan-disposition receipt ledger. Each checkpoint has its own provider, owner-scoped anchor namespace, CAS sequence, source digest, marker, policy binding, enrollment flow, freshness status, reconciliation, and marker-recovery endpoints.

The status-transition snapshot preserves the transition event chain and attestation bytes. The disposition snapshot preserves signed orphan-disposition receipts. Both source readers reject structurally unhealthy ledgers; the transition audit separately verifies Ed25519 attestations, signing-key lifecycle cutoff, current-pointer bindings, and historical validity.

## Continuity and crash recovery

Before appending a new transition or disposition, an enabled checkpoint must be enrolled and current. After a local append, the checkpoint is advanced only when exactly one event can be removed to reconstruct the previously anchored snapshot. Multi-event gaps, rollback, policy drift, invalid markers, or unavailable providers fail closed. If an external CAS fails after the local receipt is persisted, the operation reports a pending checkpoint state and the same event can be reconciled without duplication.

Disposition application has an idempotent crash-recovery path for the case where the signed disposition event is present but the challenge record was not finalized. It verifies the original challenge, target intent, signing-key binding, transition snapshot, lifecycle snapshot, event attestation, and checkpoint continuity before finalizing the challenge.

## Decision-gate enforcement

The closure audit includes both checkpoint states. A missing, stale, behind-local, rollback-suspected, policy-drifted, or otherwise non-current required checkpoint prevents current-decision use and prevents declaring closure complete. An orphan disposition remains operational closure only; it never makes the orphaned evidence usable for a current decision.

## Configuration

- `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_STATUS_TRANSITION_ANCHOR_URL`
- `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_STATUS_TRANSITION_ANCHOR_TOKEN`
- `AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_STATUS_TRANSITION_ANCHOR=true`
- `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_ORPHAN_DISPOSITION_ANCHOR_URL`
- `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_ORPHAN_DISPOSITION_ANCHOR_TOKEN`
- `AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_ORPHAN_DISPOSITION_ANCHOR=true`

The providers and endpoints must be distinct from each other and from every other configured trust domain. Private keys are not included in the source archive.

## Application API

- `getRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointStatus`
- `reconcileRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint`
- `auditRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint`
- `getRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointStatus`
- `reconcileRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpoint`
- `auditRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpoint`

Authenticated HTTP routes expose checkpoint status, enrollment, reconciliation, audit, marker-recovery inspection, and marker recovery for both domains.

## Operational boundaries

- Enrollment does not prove history that existed before enrollment.
- External CAS and local storage are not a single distributed transaction; persisted local events plus idempotent reconciliation handle the crash window.
- Only a uniquely provable one-event gap is automatically reconcilable.
- Multi-event gaps and rollback require explicit investigation and are not silently repaired.
- HTTP listener startup depends on the runtime having the declared `express` dependency installed.

No GitHub commit was made.

## Validation results

- Batch 188 focused regression tests: 6/6 passed.
- Batch 187 regression tests after integration: 5/5 passed.
- Batch 186 regression tests: 16/16 passed in four bounded name-pattern groups.
- Batch 185 regression tests: 8/8 passed in bounded groups.
- Total targeted Batch 185–188 test cases completed: 35/35 passed.
- JavaScript/MJS/CJS syntax checks: 268/268 passed.
- Relative import references: 0 missing across 268 JavaScript/MJS/CJS files.
- Full cumulative test suite was not rerun as a single job; the environment timed out on long multi-test invocations, so affected regression suites were executed in bounded groups.
- HTTP listener startup was not tested because the validation environment does not have the declared `express` package installed.
