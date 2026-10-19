# Agentic AI V4 — Batch 204

## Scope

Batch 204 adds an independently anchored continuity ledger for recovery-gate proofs, persists drift observations when the proof checkpoint is not current, and issues signed continuity attestations bound to the proof checkpoint, latest proof, audit result, and current signing-key lifecycle.

## Independent continuity trust domain

- Domain: `cross_domain_recovery_intent_closure_recovery_gate_proof_continuity`.
- The continuity ledger is append-only and contains signed `proof_checkpoint_drift_observed` and `proof_checkpoint_continuity_attested` events.
- Its deterministic source snapshot is externally checkpointed through a provider independent from every other configured anchor domain.
- Enrollment, status, audit, and reconciliation use the existing exact-one-event continuity gate. A missing, stale, rolled-back, reused, or policy-drifted provider blocks current-decision use.
- Strict continuity mode preflights enrollment before writing a new recovery-gate proof. Operators enroll the empty continuity ledger first.

## Drift retention and recovery

- When proof checkpoint status is not current, the system persists a signed drift observation with checkpoint fingerprint, anchor and source coordinates, policy/currentness signals, finding digest, and generation.
- Repeated observations for the same unresolved fingerprint are idempotent. A recurrence after resolution receives a new generation.
- Drift evidence is retained; monitoring does not rewrite or repair an external proof anchor.
- When the proof checkpoint becomes current again, a signed continuity attestation can resolve the previously recorded drift events.
- If the continuity event is saved locally but the external write fails, the event remains durable and reconciliation can advance the checkpoint without creating a duplicate event.
- Signing-key rotation changes the current binding and makes the prior continuity attestation stale until a new attestation is issued.

## Continuity attestation binding

Each attestation binds:

- Proof checkpoint fingerprint, snapshot digest, anchor digest/sequence, source digest/count.
- Latest proof ID, digest, and snapshot digest.
- Proof audit digest and decision status.
- Current signing-key lifecycle binding digest.
- The exact drift-event IDs resolved by the attestation.

A continuity attestation proves continuity of the recorded proof chain. It does not override a `decision_blocked` or otherwise unusable underlying proof audit. In that case, the continuity ledger can be anchored and auditable while the overall decision gate remains blocked.

## Configuration

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_ANCHOR=true
```

Strict mode is opt-in for backward compatibility. If the continuity provider is configured, it is treated as a required current-decision dependency and must be enrolled before proof-gate revalidation. The provider must be independent from the proof checkpoint, recovery-receipt checkpoint, and every other registered anchor domain. Private credentials are not included in the source ZIP.

## API

All endpoints are under:

`/api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/rollback-recovery/revalidation-lifecycle/recovery-gate/proof/continuity/`

- `GET checkpoint/status`
- `GET checkpoint/audit`
- `POST checkpoint/enrollment/prepare`
- `POST checkpoint/enrollment/apply`
- `POST checkpoint/reconcile`
- `GET audit`
- `POST drift/monitor`
- `POST attest`

All routes use application authentication and owner-scoped access.

## Validation

- Batch 204 focused tests: 8/8 PASS, run individually because the test-runner execution window is limited.
- Batch 203 regression tests: 8/8 PASS across the main test cases and separate provider-reuse, rollback, and route test files.
- JavaScript/MJS/CJS syntax, relative import resolution, archive integrity, and post-extraction tests are validated for the cumulative ZIP.
- The full cumulative `npm test` and direct HTTP listener startup are not claimed as verified.
- No GitHub commit was made.
