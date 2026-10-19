# Agentic AI V4 — Batch 273

## Scope

Renewal/revocation lifecycle for Batch 272 external attestations, including signed append-only lifecycle events, cross-generation supersession, lifecycle finalization receipts, signing-key cutoff handling, replay-safe recovery, and independent checkpoint convergence.

## Lifecycle

- `prepare`: creates an owner-scoped challenge bound to the current Batch 272 external attestation, its source finalization receipt, ledger head, key lifecycle binding, and checkpoint state.
- `apply`: requires the challenge confirmation phrase and advances one recoverable phase at a time: intent, renewed/superseded or revoked, finalized, and finalization receipt.
- `audit`: validates signatures, generation monotonicity, phase bindings, predecessor/supersession links, source receipt binding, receipt chain continuity, terminal revocation, key cutoff, and checkpoint currentness.
- `snapshot`: returns a read-only lifecycle/receipt summary.
- `reconcile`: resumes pending challenges and reports whether the chain is complete and usable.

## Fail-closed statuses

`unhealthy` is returned for invalid signatures or broken bindings; `recovery_required` for missing phases, receipts, or checkpoint advancement; `stale` for un-revalidated key cutoff; and `decision_blocked` for terminal revocation. An empty history remains read-only and `not_initialized`.

## API

`${batch272ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle/{prepare,apply,audit,snapshot,reconcile}` (the root continues the existing nested Batch 272 route hierarchy).

Routes are owner-scoped through the authenticated application user. No GitHub commit is performed.
