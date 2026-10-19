# Agentic AI V4 — Batch 271

## Scope

Batch 271 adds a signed renewal/revocation lifecycle for Batch 270 external attestations. It preserves the cumulative Batch 270 source and adds lifecycle challenge handling, predecessor/replacement continuity, finalization receipts, checkpoint-aware recovery, and global recovery-gate convergence.

## Lifecycle

`Intent → Renewed → Superseded → Finalized → Finalization Receipt` for renewal, and `Intent → Revoked → Finalized → Finalization Receipt` for revocation.

Challenges are owner-scoped, time-limited, bound to the current ledger head and signing-key lifecycle digest, and require an explicit confirmation phrase. Lifecycle events are signed append-only ledger entries with deterministic operation IDs.

## Safety invariants

- Only a current Batch 270 external attestation may be targeted.
- A replacement must reference its predecessor by ID and digest.
- A terminal revocation blocks later renewal.
- Finalization receipts must bind intent, action, finalization, key lifecycle, checkpoint fingerprint, and predecessor receipt.
- Missing phases/receipts are recoverable; invalid signatures or chain bindings are unhealthy.
- Checkpoint advancement is required after persisted phases and during reconciliation.
- API routes remain owner-scoped and mutation endpoints require authenticated application access.

## API

The server defines the route root as:

```js
const batch271ExternalAttestationLifecycleRoot = `${batch270ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`;
```

This preserves the existing nested Batch 270 route hierarchy.

- `POST /prepare`
- `POST /apply`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

## Validation

See `BATCH271_VALIDATION_REPORT.md` for the executed syntax, focused regression, import, archive, and extracted-source checks. The cumulative full test suite is reported separately and must not be inferred from focused regression results.
