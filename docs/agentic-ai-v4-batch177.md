# Agentic AI V4 — Batch 177

## Scope

Batch 177 adds an independent external checkpoint for the immutable bindings of CAS-finalization receipt lifecycle recovery intents, append-only recovery-decision gate audit receipts, and stricter rollback/gap guards for the central recovery-intent checkpoint.

## Attestation recovery-intent external checkpoint

Trust domain: `cross_domain_cas_finalization_receipt_lifecycle_attestation_recovery_intents`.

The checkpoint snapshot binds both:

- Recovery intents for the attestation checkpoint's own marker-recovery operations.
- CAS-finalization receipt lifecycle recovery intents whose bindings include the attestation checkpoint state.

Mutable intent status is excluded from the immutable snapshot; the event/intent digest, binding digest, source binding, event ID, operation, and creation time are retained. This lets the checkpoint preserve a stable history while an intent progresses from prepared to completed.

Configure the independent provider with:

```bash
AGENTIC_CROSS_DOMAIN_CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION_RECOVERY_INTENT_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION_RECOVERY_INTENT_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION_RECOVERY_INTENT_ANCHOR=true
```

The provider endpoint must be unique across trust domains. Required mode fails application initialization if no provider is configured. The first enrollment over non-empty history preserves `historyNotProven`; it does not establish retroactive trust.

Before an attestation checkpoint marker-recovery action runs, its recovery intent is persisted and the dedicated checkpoint is advanced when configured. In required mode, marker recovery is blocked until this checkpoint is anchored and fresh. The checkpoint source is audited independently from the attestation-event checkpoint.

## Recovery-decision gate audit receipt

Every completed freshness/replay decision-gate audit attempts to append a receipt to an owner-scoped, hash-linked ledger. Each receipt records:

- The decision status and whether the decision was usable.
- The checkpoint domains and observed anchor digests/sequences.
- A binding digest over the inspected checkpoint and nested-audit summaries.
- The finding set and its digest.
- Sequence, previous-event digest, and creation time.

The ledger is append-only and uses optimistic concurrency control. Its audit verifies the record digest, event chain, sequence, and evidence/reason digests. If the ledger is unhealthy or the new receipt cannot be persisted, the decision gate fails closed. A valid local digest chain is tamper-evident but is not equivalent to an external signature or independent external anchoring.

API: `GET /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/audit`.

## Recovery-intent rollback/gap guard

Central recovery-intent checkpoint reconciliation now accepts only:

- An already-current anchored checkpoint (idempotent result).
- A validated `marker_pending` state that the checkpoint service can reconcile.
- A `behind_local` state with exactly one new event whose removal reconstructs the previous anchored snapshot digest uniquely.

Rollback, policy drift, unavailable/invalid provider state, unproven continuity, and multi-event gaps are rejected. No automatic history rewriting, deletion, or compaction is introduced.

## API endpoints

- `GET /api/agentic/recovery-audit/cross-domain/checkpoints/attestation-recovery-intents/status`
- `POST /api/agentic/recovery-audit/cross-domain/checkpoints/attestation-recovery-intents/reconcile`
- `POST /api/agentic/recovery-audit/cross-domain/checkpoints/attestation-recovery-intents/enrollment-challenges`
- `POST /api/agentic/recovery-audit/cross-domain/checkpoints/attestation-recovery-intents/enrollment-challenges/:id/apply`
- `GET /api/agentic/recovery-audit/cross-domain/checkpoints/attestation-recovery-intents/audit`
- `GET /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/audit`

All routes use the existing authenticated, owner-scoped middleware.

## Integrity rules

- Recovery-intent checkpoint snapshots cover both marker-recovery intents and lifecycle-operation intents.
- A recovery intent is persisted before the protected marker-recovery action.
- Required marker recovery fails closed if its recovery-intent checkpoint is not anchored and fresh.
- Multi-event gaps and rollback are never silently reconciled.
- Decision-gate receipts bind the decision to the evidence observed during that audit.
- A corrupted receipt ledger makes the decision gate non-usable.
- No evidence deletion or automatic compaction is introduced.

## Validation record

- Batch 177 focused suite: 9/9 passing.
- Batch 176–177 combined suite: 15/15 passing.
- Batch 165–177 regression suite: 74/74 passing.
- JavaScript/MJS/CJS syntax and relative-import checks pass.
- ZIP archive integrity and extracted-source hash comparisons pass.
- Full all-in-one test invocation exceeded the environment's 300-second runtime limit after 1,128 passing test results had been emitted; no `not ok` entry appeared in that captured output. Consequently, a full cumulative pass is not claimed from that single invocation. Relevant regression files and additional file groups were executed separately.
- HTTP listener startup was not tested in this environment; route mapping and application API exports were checked.
