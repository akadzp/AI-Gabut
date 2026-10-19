# Agentic AI V4 — Batch 191

## Recovery-receipt checkpoint marker recovery, lifecycle CAS finalization, and key-cutoff revalidation

Batch 191 adds a dedicated signed append-only journal for recovery of the local marker belonging to the `cross_domain_recovery_intent_closure_recovery_receipts` external checkpoint. The journal is intentionally stored separately from the source ledger it is repairing, so recording the recovery intent does not change the source snapshot whose marker is being reconstructed.

### Persistent marker-recovery workflow

- Inspect the external anchor and local marker without mutation.
- Persist a signed recovery-intent event bound to the exact anchor digest/sequence, source digest/count, previous-anchor digest, policy digest, domain, and recovery-intent digest.
- Recover the marker only when the source and external anchor still match the persisted intent.
- Persist a signed finalization receipt after the marker is verified as current.
- On retry, reuse the same intent and finalization receipt. If the marker was written before interruption but the finalization receipt was not, the next run recognizes the already-current marker and completes the same intent.
- Reject caller-supplied anchor fields that differ from the persisted intent.

The journal uses the existing Ed25519 signing-key lifecycle and a CAS-protected append-only ledger. Audit detects invalid chain/digests, duplicate operation IDs, orphaned pending intents, mismatched finalization bindings, and signing-key cutoffs. A key cutoff does not erase historical evidence; it marks the finalization evidence stale for current-decision use.

### Freshness lifecycle CAS finalization

Batch 191 hardens renewal/revocation challenge recovery:

- A prepared challenge may expire before an event is appended; after expiry, a new lifecycle event is rejected.
- If the signed lifecycle event was already appended before an external checkpoint interruption, retry may resume that exact operation after challenge expiry, but only after historical signature and binding validation.
- Challenge finalization records the key lifecycle binding observed at finalization and whether the event became stale across a key cutoff.
- CAS conflicts are accepted only if the concurrently persisted completed challenge points to the same lifecycle event digest. External checkpoint advancement retries the same idempotent one-event continuity gate up to three times and re-reads state after a concurrent CAS win.
- Revocation receipts are now signature-verified during freshness audit. A corrupted revocation signature is an unhealthy finding rather than being accepted merely because a revocation record exists.

### API surface

- `inspectRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecovery`
- `prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent`
- `recoverRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint`
- `auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecovery`

HTTP routes are provided under `/api/agentic/recovery-audit/cross-domain/recovery-intent-closure/recovery-receipt-checkpoint/recovery/` for `inspect`, `prepare`, `recovery`, and `audit`.

### Validation

- Batch 191 focused tests: 8/8 PASS.
- Batch 190 regression: 7/7 PASS after Batch 191 changes.
- Coverage includes marker recovery, interruption after marker persistence but before receipt finalization, caller-binding mismatch, expired lifecycle retry after key cutoff, stale finalization after key rotation, and revocation signature corruption.
- HTTP listener startup remains a separate environment check if `express` is unavailable.
- No GitHub commit was made.
