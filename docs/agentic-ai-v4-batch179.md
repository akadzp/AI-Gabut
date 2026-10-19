# Agentic AI V4 — Batch 179

## Scope

Batch 179 adds Ed25519 attestations for cross-domain recovery decision-gate audit receipts, explicit recovery inspection/execution for pending receipt checkpoints, and fail-closed reconciliation rules for rollback or gaps that cannot be uniquely proven.

## Decision-gate receipt attestation

Enable strict attestation with:

```bash
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_DECISION_GATE_AUDIT_RECEIPT_ATTESTATION=true
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_AUDIT_RECEIPT_ATTESTATION_MAX_AGE_MS=86400000
AGENTIC_CROSS_DOMAIN_RECOVERY_DECISION_GATE_AUDIT_RECEIPT_ATTESTATION_FUTURE_SKEW_MS=60000
```

Strict mode reuses the configured Ed25519 signer and trusted public-key registry for drift-remediation finalization attestations. Startup fails if the signer, key ID, or trusted public key is missing. When key-lifecycle binding is required, the signing key must also be active in the finalization-key lifecycle ledger.

Receipt schema version 3 embeds an attestation that signs a canonical digest of the immutable receipt payload. The signed binding includes the decision-evidence digest, policy-state digest, source-checkpoint digest, receipt-checkpoint binding digest, signing-key fingerprint, key-lifecycle sequence/digest when present, and issue time. The attestation is embedded before the receipt event digest is computed, so the append-only receipt ledger and its external checkpoint bind the signature as well.

Verification distinguishes cryptographic/historical validity from current usability. Invalid signatures or altered bindings are `unhealthy`; expired attestations, changed policy state, or a changed signing-key lifecycle become `historically_valid_stale` and are not usable for current decisions. A historical signature remains verifiable with its trusted public key.

## Pending receipt checkpoint recovery

New API methods inspect and recover a pending decision-receipt checkpoint without appending a new decision receipt:

- `inspectRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingRecovery`
- `recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState`

Recovery can handle a missing local marker when the external anchor and source are consistent, or a single locally-ahead receipt when continuity can be uniquely proven. The recovery operation does not duplicate receipts. Rollback, policy drift, unhealthy ledgers, and multi-event gaps are blocked. Recovery may complete while historical enrollment remains `historyNotProven`; in that case `usableForCurrentDecision` remains false.

HTTP routes:

- `GET /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/:id/attestation/verify`
- `GET /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/recovery/inspect`
- `POST /api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/recovery`

## Compatibility and safety

When strict attestation is disabled, receipt schema version 2 remains in use. Strict mode deliberately rejects pre-existing unattested receipts for current use; operators must explicitly handle legacy history rather than silently treating it as attested. External anchoring remains independently configurable and is still required to establish externally verifiable continuity. The local digest chain is not a substitute for Ed25519 signature verification or provider durability.
