# Agentic AI V4 — Batch 275

Batch 275 adds a signed renewal/revocation lifecycle for Batch 274 external attestations. It uses owner-scoped prepare/apply/audit/snapshot/reconcile APIs and appends lifecycle events and finalization receipts to the existing proof-continuity ledger.

## Lifecycle

- `intent`: records the requested action, active target attestation, source finalization receipt, reason digest, current signing-key lifecycle binding, and challenge generation.
- `renewed`: creates a signed replacement linked to the prior active attestation.
- `revoked`: records terminal revocation of the active attestation.
- `superseded`: binds the predecessor to the replacement for renewal operations.
- `finalized`: records the action event selected for finalization.
- `finalization_receipt_finalized`: records a signed receipt bound to the finalization event, source checkpoint, lifecycle audit digest, key-cutoff state, and predecessor receipt.

The operation is replay-safe through deterministic phase operation IDs and challenge binding. A retry resumes existing phases instead of creating duplicate events. Conflicting operation bindings, invalid signatures, orphan phases, broken predecessor chains, or invalid receipt digests fail closed.

## Preconditions and recovery

Batch 274 external-attestation audit must be `verified_current` before a new lifecycle challenge is accepted. The active target must be the latest valid Batch 274 attestation or a verified Batch 275 replacement. Terminal revocation blocks later renewals. A key change before intent persistence invalidates the prepared challenge; a key change after intent persistence is recorded and requires revalidation.

Recovery audits lifecycle phases and receipts, resumes pending challenges, and coordinates checkpoint advancement. Missing receipts remain `recovery_required`; invalid chains are `unhealthy`; verified terminal revocation is `decision_blocked`.

## Integration

- Ledger schema and event allow-lists include Batch 275 event types.
- Independent checkpoint snapshots include Batch 275 lifecycle events and receipts.
- Application wrappers advance checkpoints after mutations and reconcile incomplete phases.
- Overall recovery-gate convergence includes Batch 275 status and generation-binding digest.
- Owner-scoped HTTP endpoints expose `prepare`, `apply`, `audit`, `snapshot`, and `reconcile`.

No GitHub commit is made by this batch.
