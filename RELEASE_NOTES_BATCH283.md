# Release Notes — Batch 283

- Added a signed renewal/revocation lifecycle for Batch 282 external attestations.
- Added intent, renewed, revoked, superseded, finalized, and finalization-receipt events with generation, predecessor, target, source-receipt, signing-key, and checkpoint bindings.
- Added fail-closed lifecycle auditing for phase conflicts, malformed bindings, orphaned or duplicate receipts, invalid predecessor chains, terminal revocation descendants, and key-cutoff conditions.
- Added idempotent apply/resume/reconcile operations and checkpoint-aware application wrappers.
- Added owner-scoped prepare/apply/audit/snapshot/reconcile APIs and HTTP routes.
- Added Batch 283 to event validation, independent checkpoint inventory, and overall recovery-gate convergence.
- Added Batch 283 regression tests for empty-history safety, source-current preconditions, API/route/checkpoint wiring, and lifecycle schema validation.
- No GitHub commit was made.
