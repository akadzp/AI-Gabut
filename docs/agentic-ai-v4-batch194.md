# Agentic AI V4 — Batch 194

## Marker-Recovery Journal Attestation Lifecycle Recovery-Intent Anchoring

Batch 194 adds a durable, signed recovery-intent boundary and a signed CAS-finalization receipt for marker-recovery journal attestation renewal/revocation. It reuses the independently configured recovery-receipt external checkpoint; it does not introduce another provider or silently enroll an unproven history.

### Lifecycle sequence

1. Prepare the existing short-lived renewal/revocation challenge.
2. Validate the challenge, target attestation, checkpoint snapshots, key lifecycle binding, and receipt-anchor state.
3. Append a signed `marker_recovery_journal_attestation_lifecycle_recovery_intent` event to the recovery-receipt ledger.
4. Advance and verify the external recovery-receipt checkpoint before applying the lifecycle mutation.
5. Append or resume the renewal/revocation lifecycle event with the recovery-intent ID and digest bound into the event.
6. Append a signed `marker_recovery_journal_attestation_lifecycle_finalization` receipt binding the challenge, recovery intent, lifecycle event, and key-cutoff observation.
7. Advance the external checkpoint, verify it is current, then finalize the challenge record through storage CAS. The final challenge binds the resulting checkpoint anchor digest/sequence/source snapshot and finalization receipt.

The recovery-intent, lifecycle event, and finalization receipt use deterministic operation IDs. Retrying the same challenge resumes the same records rather than duplicating them.

### Recovery and key cutoff

- If external checkpoint advancement fails after the intent is persisted, the challenge remains pending and the signed intent remains available for retry.
- If the lifecycle event is persisted but checkpoint advancement or finalization is interrupted, retry resumes from that event and writes at most one finalization receipt.
- A challenge that has not crossed the persisted-intent boundary cannot be applied after expiry.
- A persisted intent whose signing-key binding no longer matches the current key lifecycle cannot initiate a new mutation; the audit reports a stale, unresolved recovery intent.
- If the lifecycle event already exists when a key cutoff occurs, recovery may finish the audit/finalization chain, but the result records the cutoff and remains unusable for a current decision.
- Rollback, invalid signatures, altered bindings, and unproven multi-event gaps are not repaired automatically.

### Audit and decision gate

`auditMarkerRecoveryJournalAttestationLifecycleRecoveryIntents` verifies the signed intent and finalization chains, challenge integrity, lifecycle-event references, CAS finalization binding, key-cutoff state, and current recovery-receipt checkpoint. Pending or stale recovery lifecycle evidence blocks closure and current-decision use.

### HTTP endpoint

`GET /api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/lifecycle/recovery-intents/audit`

The endpoint uses the authenticated owner and is read-only.

### Configuration and operational limits

No new environment variable is required. The existing recovery-receipt external checkpoint must be configured and enrolled when strict anchoring is required. The recovery-intent/finalization events are externally anchored as part of that ledger. Local storage and the external provider are not one distributed transaction; recovery uses persistent signed events, operation IDs, CAS, and checkpoint reconciliation.

No private key material is included in the archive.
