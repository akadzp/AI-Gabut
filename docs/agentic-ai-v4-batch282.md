# Agentic AI V4 — Batch 282

## Scope
Batch 282 externally attests Batch 281 lifecycle finalization receipts. It preserves the cumulative source tree and binds every attestation to a specific receipt and its finalization event, the receipt-chain prefix, source checkpoint, source lifecycle audit, and current signing-key lifecycle binding.

## Attestation and audit
- The source lifecycle must be complete and either `verified_current` or terminally `decision_blocked`; malformed or incomplete receipt chains are rejected.
- Attestations are appended to the signed ledger with deterministic operation IDs.
- Each attestation records its generation and predecessor ID/digest, enabling continuity checks across re-attestation after binding changes.
- Audit verifies historical signatures, source receipt/finalization binding, chain prefix digest, checkpoint fingerprint, signing-key binding, key-cutoff state, and missing attestations.
- Terminal source revocation remains `decision_blocked`; invalid signatures or chain bindings fail closed as `unhealthy`.

## Recovery and integration
- Reconciliation resumes source lifecycle work first, advances an independent checkpoint before attestation, creates/reuses attestations, advances the checkpoint again, and audits the result.
- Batch 282 events are included in the cumulative ledger event allowlist and independent checkpoint snapshot inventory.
- The global recovery-gate convergence status and generation binding digest include Batch 282 state.

## HTTP
Owner-scoped routes are mounted under the Batch 281 lifecycle root plus `/finalization-receipts/external-attestations`, with `attest`, `audit`, `snapshot`, and `reconcile` endpoints.

## Validation limits
The focused tests and syntax/archive checks are reported in `BATCH282_VALIDATION_REPORT.md`. Full cumulative `npm test`, a positive end-to-end flow with a current Batch 281 receipt chain, and an actual HTTP listener startup are not claimed unless separately executed successfully.
