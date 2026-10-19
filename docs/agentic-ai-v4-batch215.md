# Agentic AI V4 — Batch 215

## Scope

Batch 215 adds signed external attestation for finalized finalization-attestation lifecycle receipts, an independent checkpoint for those attestations, replay-safe recovery after anchor-write failure, and decision-gate enforcement when the latest lifecycle receipt attestation is missing, stale, revoked by its underlying lifecycle state, or not externally current.

## Signed attestation event

- `proof_continuity_finalization_attestation_lifecycle_receipt_lifecycle_attested`

Each event binds the finalized lifecycle event ID/digest, the receipt ID/digest being attested, lifecycle generation and status, the independent receipt checkpoint fingerprint and anchor metadata, and the current signing-key lifecycle binding. Event generation is monotonic. A repeated attestation for the same current lifecycle receipt reuses the original event.

The attestation event is stored in the signed append-only proof-continuity ledger. It is deliberately excluded from the source projection of the receipt checkpoint it attests, avoiding a circular dependency. It is included in the general proof-continuity ledger and a dedicated external attestation checkpoint.

## Independent checkpoint

Trust domain: `cross_domain_finalization_attestation_receipt_lifecycle_attestations`

The checkpoint projection contains only receipt-lifecycle attestation events. It has independent enrollment, status, audit, and reconciliation operations. Provider or endpoint reuse against any registered anchor domain is rejected.

### Environment configuration

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ATTESTATION_ANCHOR_URL=https://your-independent-anchor
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ATTESTATION_ANCHOR_TOKEN=your-token
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ATTESTATION_ANCHOR=true
```

When configured, successful receipt-lifecycle renewal or revocation automatically triggers attestation and checkpoint advancement. If the external write fails, the signed event remains persisted and the operation reports `recovery_required`; retry resumes the same event without duplication. New receipt-lifecycle operations are blocked while this checkpoint is stale.

## API routes

Under the recovery-gate proof-continuity API root:

- `POST finalization-attestation-lifecycle-receipt/attest`
- `GET finalization-attestation-lifecycle-receipt/attestation/audit`
- `GET finalization-attestation-lifecycle-receipt-attestation-checkpoint/status`
- `GET finalization-attestation-lifecycle-receipt-attestation-checkpoint/audit`
- `POST finalization-attestation-lifecycle-receipt-attestation-checkpoint/enrollment/prepare`
- `POST finalization-attestation-lifecycle-receipt-attestation-checkpoint/enrollment/apply`
- `POST finalization-attestation-lifecycle-receipt-attestation-checkpoint/reconcile`

## Recovery and decision-gate behavior

- Attestation is only created for a finalized, signed lifecycle receipt and a current receipt checkpoint.
- A receipt renewal/revocation automatically creates a new attestation generation once the lifecycle operation has completed.
- The attestation checkpoint is independent from the receipt checkpoint and is included in cross-domain convergence.
- External write failure leaves the attestation event recoverable; retry does not create duplicate attestations.
- A stale or unanchored attestation blocks new receipt-lifecycle operations and current-decision use.
- Revocation remains terminal. Attesting a revocation records independently anchored history but never makes the revoked receipt usable.

## Validation recorded for Batch 215

- Batch 215 focused tests: 4/4 passed individually after extraction.
- Batch 214 renewal, revocation, and checkpoint-write recovery compatibility tests: 3/3 passed individually after extraction.
- Syntax and relative-import validation are performed against the complete source tree and repeated after ZIP extraction.
- The combined Batch 215 test-file invocation timed out after the first test in this environment; all four tests were run individually and passed.
- Full cumulative `npm test` is not claimed as passing.
