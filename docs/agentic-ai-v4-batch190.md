# Agentic AI V4 — Batch 190

## Recovery-receipt external anchoring, freshness lifecycle, and continuity audit

Batch 190 adds a dedicated external snapshot checkpoint for the closure checkpoint recovery-receipt ledger. The trust domain is `cross_domain_recovery_intent_closure_recovery_receipts`, with its own provider and endpoint configuration. The source snapshot is the signed append-only recovery-intent/finalization/freshness event ledger from Batch 189.

When the receipt checkpoint is configured, new recovery-receipt writes require an enrolled, fresh, current anchor before local mutation. After a receipt is appended, the service advances the anchor only when the previous anchored snapshot can be reconstructed by removing exactly one event. A local append followed by external CAS failure remains pending; retry reuses the same operation ID and receipt, and reconciliation does not synthesize missing history. Multi-event gaps, rollback, invalid markers, and policy drift remain blocked.

## Freshness attestation lifecycle

Batch 190 adds challenge-bound `renew` and `revoke` operations for closure checkpoint freshness attestations. Challenges bind the target attestation ID/digest, checkpoint snapshot, recovery-receipt ledger head, receipt-checkpoint anchor, and active signing-key lifecycle. Challenges expire within a bounded interval and require an exact confirmation string.

Renewal appends a new signed freshness-attestation event bound to the prior attestation and lifecycle challenge. Revocation appends a signed revocation event without deleting or rewriting the original attestation. A key rotation or any source/checkpoint change between preparation and application invalidates the challenge. If a lifecycle event was already appended before an external-commit interruption, retry resumes the same operation and does not duplicate the event.

Freshness verification also checks that the current recovery-receipt checkpoint contains exactly the source count captured by the latest attestation. Later receipt-ledger changes, checkpoint drift, expiration, revocation, or signing-key cutoff make that attestation unusable for current decisions.

## Continuity and decision gate

The recovery-receipt audit reports current, single-event-pending, stale, continuity-unproven, and unhealthy states. A one-event pending gap is recognized only if exactly one event removal reconstructs the anchored source digest. It is still not usable for a current decision until reconciliation completes. The closure audit includes recovery-receipt checkpoint status and continuity findings.

## API surface

- `getRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointStatus`
- `reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint`
- `prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment`
- `applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment`
- `auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint`
- `auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptContinuity`
- `prepareRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle`
- `applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle`

All HTTP endpoints use the existing authenticated application routes and owner-scoped storage.

## Configuration

- `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_ANCHOR_URL`
- `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_ANCHOR_TOKEN`
- `AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_ANCHOR=true`
- Existing `AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION=true` continues to require a current freshness attestation for closure/current-decision use.
- Existing `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_MAX_AGE_MS` remains bounded to 1,000–3,600,000 milliseconds.

The new receipt anchor must be independent from the transition, disposition, and all other trust-domain providers/endpoints. Private keys are not included in the archive.

## Validation

- Batch 190 tests: 7/7 PASS.
- Batch 185–190 focused regression tests: 47/47 PASS.
- All 177 test files were executed in controlled groups: 1,298/1,298 test cases PASS. A single monolithic invocation exceeded the 300-second runtime limit, so the complete suite was rerun and completed in smaller groups.
- JavaScript/MJS/CJS syntax: 270/270 PASS; relative imports: 0 missing.
- HTTP listener startup remains unverified if `express` is unavailable in the validation environment.
- No GitHub commit was made.
