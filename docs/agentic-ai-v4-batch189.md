# Agentic AI V4 — Batch 189

## Closure checkpoint recovery-intent receipts and freshness attestation

Batch 189 adds a durable, owner-scoped, append-only recovery ledger for marker recovery of the status-transition and orphan-disposition checkpoints. Each recovery starts with a signed recovery-intent event bound to the exact external anchor sequence/digest, source snapshot digest/count, previous-anchor digest, checkpoint policy digest, counterpart checkpoint fingerprint, and signing-key lifecycle binding.

After the local marker is recovered, a separate signed finalization event binds the same intent to the recovered anchor and records the finalization key lifecycle binding. A key change between intent preparation and finalization is explicitly recorded as `keyCutoffDetected`; the receipt is signed using the current key. Historical intent evidence remains available for audit.

## Crash recovery and replay behavior

If marker recovery succeeds but local recovery-receipt finalization is interrupted, the persisted intent remains pending. A retry inspects the external anchor, recognizes the marker as already current, reuses the same intent, and writes one finalization event. It does not create a second intent or receipt. Caller-supplied expected anchor fields are checked against the persisted intent; mismatches fail closed.

Only the uniquely verified anchor described by the inspection can be used. Source advancement, policy drift, rollback, unavailable anchors, invalid markers, or a non-current counterpart checkpoint block recovery. The checkpoint being recovered may itself be non-current because its local marker is missing; its read-only external-anchor inspection is the authority for recoverability.

## Cross-domain checkpoint freshness attestation

A signed freshness attestation binds a canonical snapshot of both transition and disposition checkpoint states, their anchor sequence/digest, source digest/count, freshness and policy state, plus the active signing-key lifecycle binding. The default maximum age is five minutes and can be configured between one second and one hour.

Verification re-reads both checkpoints and the current key lifecycle. Expiry, snapshot drift, anchor staleness, or key rotation makes the attestation stale and unusable for current decisions. When freshness attestation is required, closure cannot be declared complete without a current attestation.

## Application API and HTTP routes

- `prepareRecoverySloCrossDomainRecoveryIntentClosureCheckpointRecoveryIntent`
- `auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts`
- `getRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessSnapshot`
- `attestRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness`
- `auditRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness`

Authenticated routes expose recovery-receipt audit, checkpoint-freshness snapshot, freshness attestation, and freshness audit. Existing marker-recovery routes now use the persisted intent/finalization workflow.

## Configuration

- `AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION=true` makes a current signed freshness attestation mandatory for closure/current-decision use.
- `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_MAX_AGE_MS` defaults to `300000` and is bounded to `1000`–`3600000` milliseconds.

Private keys are not included in the source archive. The recovery receipt ledger is local append-only evidence in this batch; its own independent external checkpoint is not yet introduced. The two source checkpoint anchors remain independently configured as in Batch 188.

## Validation

- Batch 189 focused regression tests: 5/5 PASS.
- Batch 185–189 regression tests: 40/40 PASS.
- JavaScript/MJS/CJS syntax and relative-import validation: see delivery report.
- ZIP integrity and clean-extraction equivalence: see delivery report.
- HTTP listener startup remains unverified because `express` is not installed in the validation environment.
- No GitHub commit was made.
