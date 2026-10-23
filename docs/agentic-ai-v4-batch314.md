# Agentic AI V4 — Batch 314

Batch 314 adds external attestation for Batch 313 lifecycle finalization receipts. Attestations bind the receipt and finalization event to the source intent/action events, receipt-chain prefix, checkpoint fingerprint, lifecycle audit digest, signing-key lifecycle binding, key-cutoff state, and predecessor attestation.

The implementation includes ledger schema validation, idempotent attestation creation, chain audit, missing-attestation detection, snapshot/reconcile operations, independent checkpoint inventory, owner-scoped HTTP routes, and overall recovery-gate convergence.

## Recovery sequence

1. Audit Batch 313 lifecycle receipts.
2. Advance the independent checkpoint when required.
3. Attest each valid finalization receipt.
4. Advance the checkpoint again after attestation writes.
5. Re-audit the receipt and attestation chain.

Invalid receipt bindings, signature failures, or broken predecessor links fail closed. Missing attestations or stale checkpoints require recovery. A terminal source revocation remains `decision_blocked` and is not reactivated by an attestation.

See `BATCH314_STATUS.md`, `BATCH314_VALIDATION_REPORT.md`, and `RELEASE_NOTES_BATCH314.md` for implementation and verification scope.
