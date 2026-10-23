# Agentic AI V4 Batch 279 — External Attestation Lifecycle

Batch 279 introduces renewal and terminal revocation for Batch 278 external attestations. Lifecycle phases are represented by signed append-only ledger events: intent, renewed/revoked, superseded (renewal only), finalized, and finalization receipt.

The challenge is owner-scoped, binds the current target attestation and its source finalization receipt, captures the ledger head and snapshot digest, and requires an explicit confirmation phrase. Applying a challenge checks source audit status, independent checkpoint usability, target continuity, expiry, ledger immutability, and signing-key binding. Deterministic phase operation IDs support recovery after interruption.

Renewal creates a predecessor/replacement relationship and supersession record. Revocation is terminal. The audit verifies signatures, lifecycle generation, phase ordering, finalization bindings, receipt predecessor chain, source receipt, checkpoint freshness, and key-cutoff state. Missing receipts or incomplete phases require reconciliation; invalid chains fail closed.

The owner-scoped API is exposed under the Batch 278 external-attestation root with `prepare`, `apply`, `audit`, `snapshot`, and `reconcile` operations. The global recovery gate incorporates Batch 279 status and generation-binding digest.

See `BATCH279_VALIDATION_REPORT.md` for the validated test scope and limitations.
