# Release Notes — Batch 311

## Added
- Renewal and terminal revocation lifecycle for Batch 310 external attestations.
- Signed intent, renewed/revoked, superseded, finalized, and finalization-receipt events.
- Binding to the active Batch 310 attestation, its source finalization receipt, challenge/action, reason digest, signing-key lifecycle, checkpoint state, and predecessor/replacement IDs and digests.
- Cross-generation supersession and receipt-chain validation.
- Idempotent phase recovery and checkpoint advancement wrappers.
- Overall recovery-gate convergence integration and owner-scoped `prepare`, `apply`, `audit`, `snapshot`, and `reconcile` routes.
- Focused Batch 311 regression tests.

## Safety behavior
- A Batch 310 source attestation must be verified-current before a lifecycle mutation can be prepared.
- Invalid actions, reasons, and challenge TTL values are rejected before mutation.
- A finalized terminal revocation remains decision-blocking; renewal cannot reactivate a revoked target.
- Missing finalization receipts require recovery; invalid signatures, bindings, or predecessor chains produce an unhealthy audit.

## Validation note
Focused regression suites passed when run separately. The full cumulative `npm test`, positive end-to-end provisioning of the full upstream chain, crash injection at every phase boundary, and live HTTP startup are not claimed as complete.

## GitHub
No commit made.
