# Roadmap — Batch 295

## Completed

- Renewal and revocation lifecycle for Batch 294 external attestations.
- Signed predecessor-to-replacement continuity and terminal revocation handling.
- Lifecycle-specific finalization receipts and replay-safe phase operation IDs.
- Signing-key lifecycle and key-cutoff checks.
- Independent checkpoint reconciliation and overall recovery-gate convergence integration.
- Owner-scoped application APIs and HTTP routes.
- Focused regression, syntax, and archive validation.

## Validation gaps retained explicitly

- Full cumulative `npm test` exceeded the 300-second execution limit at subtest 1129 and did not produce a final summary.
- Positive end-to-end lifecycle execution from a verified-current Batch 294 source chain remains to be demonstrated.
- Live HTTP listener startup remains unverified.

## Next stage

**Batch 296 — External Attestation for Batch 295 Lifecycle Finalization Receipts, Cross-Generation Receipt Continuity, and Independent Checkpoint Recovery.**

Priorities:
1. External attestation for Batch 295 lifecycle finalization receipts.
2. Cross-generation receipt-chain and predecessor-attestation continuity.
3. Recovery after interruption between receipt finalization and attestation/checkpoint advancement.
4. Signing-key cutoff and historical-signature verification.
5. Positive end-to-end tests against a verified-current Batch 295 lifecycle receipt chain.
