# Agentic AI V4 — Batch 229

## External attestation for lifecycle finalization receipts

Batch 229 adds a signed external-attestation event for each Batch 228 external-attestation lifecycle finalization receipt. The event binds the receipt ID/digest and generation, the referenced finalized lifecycle event, the source lifecycle-chain digest, source checkpoint fingerprint, signing-key lifecycle binding, key-cutoff state, and the preceding Batch 229 attestation ID/digest.

The service attests finalized receipts in generation order. Repeated calls reuse an existing attestation when the receipt binding and current signing-key binding are unchanged. Missing receipts, invalid source lifecycle state, invalid signatures, mismatched receipt/finalization bindings, missing historical receipt attestations, and broken predecessor chains fail closed.

## Independent checkpoint

The Batch 229 snapshot uses domain `cross_domain_finalization_receipt_external_attestations`. It includes Batch 228 finalization receipts and Batch 229 attestations. A separately configured provider/endpoint is required when this checkpoint is enabled; provider or normalized-endpoint reuse against another registered anchor domain is rejected.

Configuration is opt-in:

- `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_EXTERNAL_ATTESTATION_FINALIZATION_RECEIPT_ATTESTATION_ANCHOR_URL`
- `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_EXTERNAL_ATTESTATION_FINALIZATION_RECEIPT_ATTESTATION_ANCHOR_TOKEN`
- `AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_EXTERNAL_ATTESTATION_FINALIZATION_RECEIPT_ATTESTATION_ANCHOR`

The checkpoint participates in finalization checkpoint advancement and recovery-gate convergence. Existing deployments remain compatible when the new checkpoint is not configured and no Batch 229 attestation events exist.

## HTTP surface

Authenticated routes are registered for attestation, audit, checkpoint status/audit, enrollment prepare/apply, and checkpoint reconciliation under:

`/api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/lifecycle/recovery-intent-disposition/checkpoint/rollback-recovery/revalidation-lifecycle/recovery-gate/proof/continuity/finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/finalization-receipt-attestation`

## Validation

- Batch 229 focused tests: 3/3 PASS.
- Focused Batch 223–229 regression tests: 15/15 PASS.
- JavaScript/MJS/CJS syntax and archive integrity are validated separately during packaging.
- The broader Batch 220–229 combined test command exceeded the execution budget. Full cumulative `npm test`, positive end-to-end renewal/revocation with external checkpoint failure injection, and live HTTP startup are not claimed as passing.
