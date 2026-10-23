# Release Notes — Agentic AI V4 Batch 280

Batch 280 adds signed external attestations for Batch 279 lifecycle finalization receipts, with cross-generation receipt continuity and independent-checkpoint-aware recovery.

## Included
- New Batch 280 attestation event and strict ledger schema validation.
- Receipt binding to Batch 279 lifecycle finalization event, intent/action evidence, target attestation, source receipt, receipt-chain prefix, checkpoint fingerprint, lifecycle audit digest, and signing-key lifecycle bindings.
- Monotonic attestation generations and predecessor ID/digest continuity.
- Idempotent attestation reuse when the binding and current signing-key lifecycle remain unchanged.
- Key-cutoff detection and explicit revalidation binding when signing-key lifecycle changes.
- Owner-scoped attest/audit/snapshot/reconcile APIs and HTTP routes.
- Pre-attestation and post-attestation independent checkpoint advancement through the application reconciliation wrapper.
- Integration into the overall recovery-gate status, digest, and usability decision.
- Focused Batch 280 regression coverage.

## Validation scope
The Batch 280, Batch 279, Batch 278, Batch 277, Batch 276, Batch 104, Batch 102, and artifact-focused regression suites passed in the isolated run reported in `BATCH280_VALIDATION_REPORT.md`. Syntax, import/API checks, archive integrity, and extracted-source equality were also checked. The full cumulative `npm test` suite and a complete positive end-to-end lifecycle chain are not claimed as passed.
