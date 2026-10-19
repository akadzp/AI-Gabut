# Agentic AI V4 — Batch 267

## Renewal/revocation lifecycle for Batch 266 external attestations

Batch 267 adds a signed, append-only lifecycle for renewing or terminally revoking Batch 266 external attestations. The lifecycle emits intent, renewed/revoked, superseded, finalized, and finalization-receipt events, and binds each phase to the source attestation, source finalization receipt, challenge, generation, key lifecycle, and checkpoint.

### Invariants

- Only a verified-current Batch 266 external-attestation chain can be targeted for mutation.
- Lifecycle generations are monotonic and operation IDs are deterministic for safe retries.
- Renewal creates a predecessor-linked replacement; supersession and finalization must match the replacement event.
- Revocation is terminal and blocks later lifecycle descendants.
- Each finalized operation requires exactly one signed finalization receipt with a valid predecessor chain.
- Missing finalization receipts or incomplete phases require recovery; invalid signatures or bindings make the chain unhealthy.
- Independent checkpoint advancement occurs around mutations and during reconciliation.
- Batch 267 status is incorporated into global recovery-gate convergence and decision usability.

### API

Routes are owner-authenticated under `/finalization-receipts/external-attestations/lifecycle`:

- `POST /prepare`
- `POST /apply`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

### Recovery order

`Batch 266 attestation audit → pre-mutation checkpoint → lifecycle intent/action → finalization receipt → checkpoint advancement → final audit`.

Empty history is read-only and cannot fabricate lifecycle events or receipts.
