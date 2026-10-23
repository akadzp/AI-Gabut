# Agentic AI V4 — Batch 287

## Scope

Batch 287 adds a signed renewal/revocation lifecycle for Batch 286 external attestations, including cross-generation supersession, lifecycle finalization receipts, replay protection, signing-key cutoff handling, and independent checkpoint recovery.

## Lifecycle

- `intent` records the requested renewal or revocation.
- `renewed` records a replacement attestation and binds its predecessor.
- `superseded` binds the predecessor to the replacement action.
- `revoked` records a terminal revocation.
- `finalized` binds the completed action to its source and challenge.
- `finalization_receipt_finalized` records a signed receipt chained to the preceding lifecycle receipt.

Each lifecycle mutation is challenge-bound and owner-scoped. A challenge captures the source attestation ID/digest, source finalization receipt ID/digest, ledger head and snapshot digest, generation, and signing-key lifecycle binding. Applying a challenge checks those preconditions before the first intent event is written.

## Recovery and audit

The audit checks event signatures, challenge/generation continuity, phase cardinality, target identity, replacement/supersession binding, terminal-revocation descendants, finalization-to-receipt correspondence, receipt predecessor continuity, source receipt binding, checkpoint currency, and signing-key cutoff status. Missing receipts and incomplete challenges remain recoverable; malformed chains fail closed.

The reconciliation wrapper first reconciles Batch 286 external attestations, advances the independent checkpoint where required, resumes pending lifecycle challenges, and re-audits the resulting chain. Overall recovery-gate convergence includes the Batch 287 lifecycle status and generation binding digest.

## API

The owner-scoped HTTP routes are mounted below the Batch 286 external-attestation root plus `/lifecycle`:

- `POST /prepare`
- `POST /apply`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

No GitHub commit is part of this batch workflow.
