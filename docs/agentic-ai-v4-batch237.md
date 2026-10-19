# Agentic AI V4 — Batch 237

## External finalization receipts for Batch 236 lifecycle operations

Batch 237 adds signed finalization receipts for completed Batch 236 external-attestation lifecycle operations. The receipt ledger binds the finalization event to its intent/action chain, source attestation, source finalization receipt, key-lifecycle state, and receipt predecessor.

### Guarantees

- A receipt is created only for a finalized Batch 236 lifecycle operation with a valid source audit.
- Renewal receipts bind the renewed event, supersession event, and replacement attestation; revocation receipts bind the terminal revocation action without a replacement.
- Receipt generations are ordered and predecessor-linked. Missing predecessor receipts prevent later-generation receipt creation.
- Operation IDs are deterministic; identical retries reuse a receipt and conflicting bindings are rejected by the continuity ledger.
- Audit verifies signatures, source bindings, receipt binding digests, receipt order, missing/orphan receipts, key-cutoff state, and checkpoint freshness.
- Reconciliation can recreate missing receipts from already-finalized lifecycle events and re-audits after checkpoint advancement.
- Empty history is read-only and produces no fabricated receipt.
- Overall recovery-gate convergence incorporates Batch 237 when Batch 236 finalizations exist.

### API routes

Routes extend the Batch 236 lifecycle root with `/finalization-receipts`:

- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

Routes use the existing authenticated owner identity. No new provider or credentials are bundled.

### Validation scope

Batch-specific tests cover empty-history fail-closed behavior and service/application/route wiring. These focused checks do not imply a full live-provider end-to-end renewal/revocation run.
