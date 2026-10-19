# Agentic AI V4 — Batch 173

## Scope

Batch 173 adds three independent evidence controls:

1. External snapshot checkpointing for the remediation-finalization signing-key lifecycle.
2. External checkpointing for the cross-domain replay-incident ledger.
3. Immutable CAS-finalization receipts bound to the recovery intent, execution record, finalization record, and finalization checkpoint postcondition, with a separate receipt-ledger checkpoint.

All three trust domains require independent provider endpoints. Providers must support `read(scope)` and compare-and-set semantics through `compareAndSet(scope, expectedDigest, candidate)`.

## Environment configuration

Configure each provider independently when enabled:

```bash
AGENTIC_CROSS_DOMAIN_DRIFT_REMEDIATION_FINALIZATION_KEY_LIFECYCLE_ANCHOR_URL=https://your-key-lifecycle-anchor
AGENTIC_CROSS_DOMAIN_DRIFT_REMEDIATION_FINALIZATION_KEY_LIFECYCLE_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_DRIFT_REMEDIATION_FINALIZATION_KEY_LIFECYCLE_ANCHOR=true

AGENTIC_CROSS_DOMAIN_REPLAY_INCIDENT_LEDGER_ANCHOR_URL=https://your-replay-incident-anchor
AGENTIC_CROSS_DOMAIN_REPLAY_INCIDENT_LEDGER_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_REPLAY_INCIDENT_LEDGER_ANCHOR=true

AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CAS_FINALIZATION_RECEIPT_ANCHOR_URL=https://your-cas-receipt-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CAS_FINALIZATION_RECEIPT_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CAS_FINALIZATION_RECEIPT_ANCHOR=true
```

Do not reuse an endpoint or provider instance across trust domains. The application rejects duplicate provider instances and duplicate configured endpoints.

## Enrollment and reconciliation

Each checkpoint has status, audit, enrollment-challenge, enrollment-apply, and reconcile endpoints under:

- `/api/agentic/recovery-audit/cross-domain/drift-remediation/finalization-key-lifecycle/checkpoint/`
- `/api/agentic/recovery-audit/cross-domain/checkpoints/replay-incidents/checkpoint/`
- `/api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipts/checkpoint/`

Enrollment requires a non-empty, valid local source. The enrollment snapshot is marked `historyNotProven`; this status is not cleared automatically. Normal reconciliation advances one uniquely provable event at a time and rejects ambiguous multi-event gaps, policy drift, rollback, or unhealthy source records.

## CAS finalization receipts

`POST /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipts` accepts an `intentId`. It creates or returns an idempotent receipt only when exactly one valid execution and finalization record bind to that intent. The receipt stores a digest of the CAS result/postcondition and the finalization checkpoint state observed at issuance.

A receipt with a local-only, pending, stale, or history-unproven checkpoint is retained for audit but is not eligible for current decisions. Receipts and ledger history are append-only; no deletion or compaction is performed.

## Operational limitations

- External commit and local marker persistence are not a single distributed transaction; crash recovery must verify the external postcondition before completing local state.
- Enrollment does not prove pre-enrollment history retroactively.
- Replay-incident checkpointing is deliberately excluded from the generic checkpoint loop that generates incident findings, avoiding a self-referential incident cascade. It is checked separately by the freshness/replay audit.
- Runtime HTTP listener startup still requires the declared `express` dependency to be installed in the deployment environment.
