# Agentic AI V4 — Batch 176

## Scope

Batch 176 adds an independent external checkpoint for CAS-finalization receipt lifecycle attestations, intent-bound recovery for that checkpoint's local marker, and recovery-decision-gate integration with cross-domain recovery-intent integrity.

## Attestation-history checkpoint

The new trust domain is `cross_domain_cas_finalization_receipt_lifecycle_attestations`. Its immutable snapshot contains lifecycle event ID/digest/type and the attached Ed25519 attestation. The checkpoint is independent of the receipt-lifecycle event checkpoint; both are audited separately.

Configure it with:

```bash
AGENTIC_CROSS_DOMAIN_CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION_ANCHOR=true
```

The provider endpoint must be unique among trust domains. If the checkpoint is required but no provider is configured, application initialization fails closed. Enrollment against non-empty local history preserves `historyNotProven`; it cannot establish retroactive trust.

## Lifecycle recovery binding

Lifecycle recovery intents now bind the attestation-checkpoint state observed before the event is appended. The immutable lifecycle event repeats that binding digest. Recovery-intent audit verifies the link between event and intent. When configured, lifecycle finalization advances the event checkpoint and attestation checkpoint independently. The recovery intent records both checkpoint postconditions.

Missing-marker recovery is permitted only when the checkpoint service's recovery plan proves the exact external anchor and source postcondition. A missing local marker is treated as a recoverable condition only when that is the sole audit finding; policy drift, rollback, source corruption, and ambiguous continuity remain blocked.

## Recovery decision gate

`auditRecoverySloCrossDomainCheckpointFreshnessReplay` now includes:

- Cross-domain recovery-intent ledger integrity audit.
- Current lifecycle-attestation verification.
- Independent lifecycle-attestation checkpoint audit.

Unhealthy or pending recovery intents, stale required attestations, or a required attestation checkpoint that is not current make the decision gate non-usable. Audit remains read-only except for the existing append-only replay-incident recording behavior.

## API endpoints

- `GET /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipt-lifecycle/attestation-checkpoint/status`
- `POST /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipt-lifecycle/attestation-checkpoint/reconcile`
- `POST /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipt-lifecycle/attestation-checkpoint/enrollment-challenges`
- `POST /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipt-lifecycle/attestation-checkpoint/enrollment-challenges/:id/apply`
- `GET /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipt-lifecycle/attestation-checkpoint/audit`
- `GET /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipt-lifecycle/attestation-checkpoint/recovery/inspect`
- `POST /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipt-lifecycle/attestation-checkpoint/recovery`

All endpoints use the existing authenticated, owner-scoped middleware.

## Integrity rules

- Attestation events remain append-only; no evidence deletion or automatic compaction is introduced.
- A missing marker may be restored only from a matching external anchor and a persisted recovery intent.
- Multi-event gaps, policy drift, rollback, and unproven continuity are not silently repaired.
- Enrollment against existing history preserves the `historyNotProven` state.
- The decision gate fails closed for an unhealthy recovery-intent ledger or a required attestation checkpoint that is not current.

## Validation record

The focused Batch 176 suite passes 6/6 tests. The Batch 165–176 regression set passes 65/65 tests. All 163 test files were executed in bounded groups, totaling 1,188/1,188 passing tests. An initial all-at-once run exceeded the environment's runtime limit and one existing Batch 104 lease-heartbeat test failed under concurrent load; it passed when isolated and in the bounded rerun. JavaScript/MJS/CJS syntax and relative-import checks passed. HTTP listener startup was not tested.
