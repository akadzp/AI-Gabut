# Agentic AI V4 — Batch 205

## Scope

Batch 205 adds lifecycle renewal/revocation for recovery-gate proof-continuity attestations, append-only supersession evidence, explicit drift-resolution receipt finalization, and cross-generation replay protection.

## Attestation lifecycle

- Lifecycle operations require an explicit `renew` or `revoke` challenge, a reason of 12–240 characters, a matching confirmation phrase, and a current proof checkpoint.
- Challenges expire after ten minutes by default. Expiry blocks an operation before its intent is persisted; after a durable intent exists, recovery resumes the original operation even if the challenge expires.
- The lifecycle state machine records signed `intent`, `renewed` or `revoked`, `superseded` when renewing, and `finalized` events in the append-only proof-continuity ledger.
- Renewal generations increase monotonically. Each supersession binds the previous generation, replacement event ID/digest, target attestation, challenge, and signing-key lifecycle.
- Revocation is terminal for the exact target attestation. A revoked target cannot be renewed. A new continuity attestation created after a legitimate checkpoint/proof change is a distinct target and must pass the normal audit path.
- Lifecycle audit verifies event signatures, sequence/digest-chain integrity, finalization binding, generation order, target binding, and current signing-key lifecycle.

## Crash recovery and cutoff handling

- Every lifecycle phase has a deterministic operation ID. The application advances the existing independent continuity checkpoint after each appended event.
- If a local event is durable but external anchoring fails, the original challenge and event are resumed; duplicate intents, renewal events, supersession events, and finalization receipts are not created.
- Key rotation before intent persistence invalidates the prepared challenge. Rotation after intent persistence allows the historical operation to be finalized with cutoff recorded, but the resulting renewal remains stale and cannot authorize current-decision use.
- A revoked target remains revoked regardless of key rotation.

## Drift-resolution receipt finalization

- A continuity attestation that resolves drift is followed by a separately signed `proof_continuity_drift_resolution_receipt_finalized` event.
- The receipt binds the continuity event ID/digest, exact resolved drift-event IDs, checkpoint fingerprint, anchor/source coordinates, receipt digest, and signing-key lifecycle binding.
- The existing independent proof-continuity checkpoint anchors the finalization receipt. If the process stops between continuity attestation and receipt finalization, reconciliation completes the missing receipt(s) and advances one event at a time.
- Audit returns `recovery_required` while any continuity event that resolved drift lacks its own finalization receipt.

## API

All endpoints are under:

`/api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/rollback-recovery/revalidation-lifecycle/recovery-gate/proof/continuity/`

- `POST lifecycle/prepare` — prepare a `renew` or `revoke` challenge.
- `POST lifecycle/apply` — advance the original lifecycle operation through its durable phases.
- `GET lifecycle/audit` — audit lifecycle signatures, generations, supersession, revocation, and currentness.
- `POST drift/finalize` — finalize pending drift-resolution receipt evidence.

The endpoints use the existing application authentication and owner-scoped access middleware.

## Validation

- Batch 205 focused tests: 7/7 PASS, executed individually due to runner limits.
- Batch 204 regression tests: 8/8 PASS, executed individually.
- JavaScript/MJS/CJS syntax checks and relative import resolution passed for the cumulative source tree.
- ZIP integrity and post-extraction regression checks were performed for the delivered cumulative archive.
- Full cumulative `npm test` and direct HTTP listener startup are not claimed as verified. The runtime environment does not contain the `express` package (`ERR_MODULE_NOT_FOUND`).
- No GitHub commit was made.
