# Agentic AI V4 — Batch 175

## Scope

Batch 175 adds three controls for CAS-finalization receipt lifecycle operations:

1. Ed25519 attestations bound to revocation and replacement lifecycle events.
2. Recovery intents that survive interruption between event persistence, external checkpoint advancement, and local intent finalization.
3. A cross-domain recovery-intent integrity audit spanning checkpoint recovery intents, replay-incident CAS intents, remediation CAS/finalization records, and receipt lifecycle recovery intents.

## Lifecycle attestations

Each `revoked` or `replaced` event can carry an Ed25519 attestation. Its signed payload includes the immutable event body, sequence, previous-event digest, challenge/receipt/recovery-intent bindings, signing key ID, trusted public-key fingerprint, key-lifecycle sequence/digest when available, and issue time.

Configure the requirement and freshness bounds:

```bash
AGENTIC_REQUIRE_CROSS_DOMAIN_CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION=true
AGENTIC_CROSS_DOMAIN_CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION_MAX_AGE_MS=86400000
AGENTIC_CROSS_DOMAIN_CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION_FUTURE_SKEW_MS=60000
```

The signer and public-key registry reuse the remediation-finalization Ed25519 configuration. When attestation is required, the application fails closed if a signer or trusted public key is unavailable. When optional and unavailable, the event remains auditable but cannot claim signed attestation.

Verification distinguishes `verified_current`, `historically_valid_stale`, `unavailable`, and `unhealthy`. A later key rotation can make an attestation historical-only without invalidating a correctly verifiable historic signature.

## Lifecycle recovery intents

Revocation and replacement operations persist a recovery intent before appending the lifecycle event. The event references the intent ID and immutable recovery-intent digest. The intent binds the event ID, operation, challenge, receipt, source snapshot/count, and relevant checkpoint fingerprints.

The recovery API checks whether the expected event already exists and verifies its digest and bindings. If it exists, recovery can resume checkpoint reconciliation/marker recovery and finalize the intent. If the event is missing after intent creation, the operation is not replayed automatically; the intent remains `recovery_required` for explicit investigation.

Statuses include `completed`, `completed_local`, `completed_history_unproven`, `awaiting_enrollment`, `checkpoint_pending`, and `recovery_required`. `completed_history_unproven` does not imply current-decision usability.

## API endpoints

- `GET /api/agentic/recovery-audit/cross-domain/recovery-intents/ledger-integrity/audit`
- `GET /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipt-lifecycle/attestations/audit?current=true`
- `GET /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipt-lifecycle/events/:id/attestation/verify`
- `GET /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipt-lifecycle/recovery-intents/audit`
- `POST /api/agentic/recovery-audit/cross-domain/recovery-intents/cas-finalization/receipt-lifecycle/recovery-intents/recover`

All routes use the application authentication middleware and owner-scoped access.

## Integrity rules

- Lifecycle events and receipts remain append-only.
- Attestation, event digest, challenge, receipt, and recovery-intent bindings are independently checked.
- Checkpoint recovery is allowed only when source evidence and the external anchor prove the expected postcondition.
- Multi-event gaps, policy drift, rollback, and missing event bodies are not silently repaired.
- No evidence deletion or automatic compaction is performed.
