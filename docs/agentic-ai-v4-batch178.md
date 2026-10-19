# Agentic AI V4 — Batch 178

## Scope

Batch 178 adds independent external anchoring for recovery decision-gate audit receipts, marker crash-recovery for the attestation recovery-intent checkpoint, current checkpoint/policy-state binding, and request-id replay protection.

## Decision-gate audit receipt checkpoint

Trust domain: `cross_domain_recovery_decision_gate_audit_receipts`.

Configure the provider independently from every other trust domain:

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_AUDIT_RECEIPT_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_AUDIT_RECEIPT_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_DECISION_GATE_AUDIT_RECEIPT_ANCHOR=true
```

The checkpoint snapshots the hash-linked decision receipt ledger. A receipt binds the decision status, observed checkpoint status/freshness/anchor sequence and digest, current and anchored policy digests, policy-state digest, nested attestation and recovery-intent audit summaries, and decision-reason digest. The receipt also records the checkpoint state observed before its own append to avoid self-referential evidence.

When the provider is configured, a decision is not usable until the checkpoint is anchored, fresh, free of policy drift, and not marked `historyNotProven`. Initial enrollment over a non-empty local receipt history deliberately marks that history unproven; the implementation does not claim retroactive trust. A missing/invalid marker, rollback, policy drift, or unresolved gap blocks further receipt appends so that recovery evidence is not overwritten by additional local history.

## Request-id replay protection

`GET /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/audit?requestId=<stable-id>` accepts an optional request ID (1–128 characters from `[A-Za-z0-9._:-]`). Repeating the same request ID with the same decision/evidence/reason binding returns the existing receipt idempotently. Reusing it for a different binding is rejected as a conflict. Calls without a supplied request ID receive a generated unique ID and remain independently append-only.

Receipt schema version 2 includes `requestId`, `replayFingerprint`, `decisionEvidenceBindingDigest`, `receiptCheckpointBindingDigest`, `policyStateDigest`, and `sourceCheckpointDigest`. The audit continues to read schema-version-1 receipts for backward compatibility.

## Attestation recovery-intent checkpoint marker recovery

The existing attestation recovery-intent checkpoint now exposes inspect/recover operations. Recovery requires the exact external anchor, matching source digest/count, matching policy digest, and a valid recovery plan. Recovery intents are recorded in the central recovery-intent ledger using a filesystem-safe short ID. Missing-marker-only findings are recoverable; rollback, policy drift, invalid source evidence, and unproven continuity remain blocked.

Endpoints:

- `GET /api/agentic/recovery-audit/cross-domain/checkpoints/attestation-recovery-intents/recovery/inspect`
- `POST /api/agentic/recovery-audit/cross-domain/checkpoints/attestation-recovery-intents/recovery`
- `GET /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/checkpoint/status`
- `POST /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/checkpoint/reconcile`
- `POST /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/checkpoint/enrollment-challenges`
- `POST /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/checkpoint/enrollment-challenges/:id/apply`
- `GET /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/checkpoint/audit`
- `GET /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/checkpoint/recovery/inspect`
- `POST /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/checkpoint/recovery`

All endpoints use the existing authenticated owner-scoped middleware.

## Safety constraints

- No evidence deletion or automatic compaction is introduced.
- Rollback and policy drift are never automatically repaired.
- Reconciliation is restricted to a marker repair or a single event with uniquely proven continuity.
- External provider commits and local storage writes are not one distributed atomic transaction; recovery intents and postcondition checks are used for interrupted operations.
- Local hash chains are tamper-evident, not digital signatures. Independent external anchoring is required for the external trust claim.
- Enrollment of existing local receipt history does not prove that history retroactively.

## Validation record

- Batch 178 focused suite: 9/9 passing.
- Batch 174–177 regression suites: 30/30 passing.
- JavaScript/MJS/CJS syntax and relative-import checks pass.
- External receipt checkpoint advancement, request-id replay, changed-binding conflict, attestation recovery-intent marker recovery, and decision-receipt marker recovery are covered by regression tests.
- All 165 test files were executed in bounded groups or individually: 1,206/1,206 tests passed with zero failures. A single monolithic run is not claimed because it exceeded the environment runtime limit; the bounded-group runs completed successfully.
- HTTP listener startup was not tested in this environment; authenticated route mapping and application exports were checked.
