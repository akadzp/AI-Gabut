# Agentic AI V4 — Batch 203

## Scope

Batch 203 adds an independently anchored external checkpoint for the recovery-gate proof ledger, integrates checkpoint reconciliation into recovery-gate revalidation, and binds decision proofs to the freshness-attestation supersession audit.

## Independent proof checkpoint

- Trust domain: `cross_domain_recovery_intent_closure_recovery_gate_proofs`.
- The source snapshot is a deterministic projection of the signed, append-only proof ledger. Its event list is designed so a single-event delta can be uniquely reconstructed from the previous snapshot.
- Enrollment, status, audit, and reconciliation are exposed through application methods and HTTP routes.
- The proof checkpoint provider and endpoint must be independent from all other configured external-anchor domains. Reuse is rejected.
- When configured, proof checkpoint currentness is required before the proof audit can be used for a current decision.
- Strict gate revalidation is preflighted: if the proof checkpoint has not been enrolled, no proof event is written. Operators enroll the empty ledger first, then retry the gate. Existing unanchored history is not silently treated as proven.

## Recovery and continuity

- After a local proof event is committed, the application advances the independent proof checkpoint through the existing exact-one-event continuity gate.
- If the external write fails, the proof remains durable locally and the decision is returned as `recovery_required`; reconciliation may resume only when the single-event delta is provable.
- If an external commit succeeds but its response is lost, reconciliation repairs the local checkpoint marker from the observed anchor without appending a duplicate external anchor.
- Multi-event gaps, rollback, provider reuse, policy drift, and invalid proof-ledger history remain blocked. No external anchor is rewritten to conceal rollback.
- Proof snapshots bind the current freshness-attestation supersession audit digest in addition to the lifecycle, closure, drift, checkpoint, and signing-key evidence already bound by the proof.

## Configuration

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_ANCHOR=true
```

The provider can also be supplied through the `createAgenticApplication` options:

- `recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofAnchor`
- `requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofAnchor`

Strict mode is opt-in for backward compatibility. When enabled, the provider must be configured and enrolled before a proof can be accepted for current-decision use. Private credentials are not included in the source ZIP.

## API

All routes are under:

`/api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/rollback-recovery/revalidation-lifecycle/recovery-gate/proof/checkpoint/`

- `GET status`
- `GET audit`
- `POST enrollment/prepare`
- `POST enrollment/apply`
- `POST reconcile`

The existing proof audit and recovery-gate revalidation routes now include independent proof-checkpoint status when the checkpoint is configured.

## Validation

- Batch 203 focused regression tests: 7/7 PASS across the main suite and isolated regression files.
- Batch 202 regression tests after Batch 203 changes: 6/6 PASS.
- Syntax, relative-import resolution, archive integrity, and post-extraction regression tests are validated for the cumulative ZIP.
- Full cumulative `npm test` and direct HTTP listener startup are not claimed as verified.
- No GitHub commit was made.
