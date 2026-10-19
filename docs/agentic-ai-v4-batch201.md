# Agentic AI V4 — Batch 201

## Scope

Batch 201 adds freshness attestation for the independent rollback-revalidation lifecycle checkpoint, durable drift-evidence retention, recovery after interrupted evidence anchoring, and recovery-gate revalidation.

## Independent lifecycle freshness attestation

The new `revalidation_lifecycle_checkpoint_freshness_attested` event is signed and appended to the recovery-receipt ledger. Its payload binds:

- The independent lifecycle checkpoint domain and snapshot digest.
- Anchor digest and sequence, source digest and count, and a normalized checkpoint fingerprint.
- A digest of the lifecycle audit and retained-drift audit.
- The active signing-key lifecycle binding.
- Issue and expiry timestamps, plus a generation ID.
- The recovery-receipt checkpoint sequence observed before the attestation event was appended.

Attestation issuance requires a current independent lifecycle checkpoint, a healthy lifecycle audit, resolved/anchored drift evidence, and a current external recovery-receipt checkpoint. The receipt checkpoint must advance over the attestation event itself. The audit rejects stale snapshots, key cutoffs, expiry, generation replay, binding changes, and a receipt checkpoint that has advanced beyond the attested event.

Strict decision-gate enforcement is opt-in for backward compatibility. When enabled, missing or stale lifecycle freshness attestation blocks use of lifecycle evidence for current decisions. A current lifecycle attestation does not override unrelated closure blockers.

## Durable drift-evidence retention

When drift monitoring detects a lifecycle checkpoint or related rollback drift, it persists an immutable drift-evidence record before attempting to append a signed observation event to the recovery-receipt ledger.

The record and its external mirror use deterministic fingerprints and operation IDs. A retry after local commit but failed external checkpoint finalization reuses the same event and completes checkpoint advancement instead of duplicating the record. A new incident generation is created when the same drift state recurs after prior evidence has been resolved.

Resolution is recorded as a signed append-only event only after the relevant checkpoint and lifecycle audit are current again. Drift evidence is never used to rewrite an external anchor. Pending, invalid, unresolved, or unanchored drift evidence blocks current-decision use.

## Recovery-gate revalidation

The recovery-gate revalidation operation:

1. Runs drift monitoring and retains newly observed drift.
2. Attempts only continuity-safe checkpoint reconciliation; rollback, unhealthy state, policy drift, and unproven gaps remain blocked.
3. Reconciles pending drift-evidence events and eligible lifecycle operations.
4. Audits freshness attestation, lifecycle evidence, and aggregate closure.
5. Reports `verified_current` only when the aggregate closure and lifecycle gate both permit current-decision use.

## API

Routes are available below `/api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/rollback-recovery/revalidation-lifecycle/`:

- `POST freshness/attest`
- `GET freshness/audit`
- `GET drift-evidence/audit`
- `POST drift-evidence/reconcile`
- `POST recovery-gate/revalidate`

The existing `GET .../drift` monitoring route now also returns drift-retention and drift-audit status. Routes use application authentication and owner-scoped access.

## Configuration

```bash
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION=true
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_MAX_AGE_MS=300000
```

The maximum age is bounded from 1 second to 1 hour. The default is five minutes. Private keys are not included in the source ZIP.

## Validation

- Batch 201 focused regression tests: 7/7 PASS.
- Batch 200 focused regression tests after Batch 201 changes: 6/6 PASS.
- Batch 199: tests 1–11 passed in a serial run; tests 12–13 also passed individually. The grouped run exceeded the environment runtime after test 11, so no single completed 13-test grouped run is claimed.
- JavaScript/MJS/CJS syntax, relative imports, ZIP integrity, and post-extraction checks are recorded in the release summary.
- Direct HTTP listener startup is not claimed as verified in this environment.
- No GitHub commit was made.

## Next stage

Batch 202 — Freshness-Attestation Supersession Ledger, Drift-Resolution Receipt Continuity, and Decision-Gate Recovery Proof.
