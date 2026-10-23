# Release Notes — Batch 289

- Added Batch 289 renewal/revocation lifecycle for Batch 288 external attestations.
- Added signed lifecycle phases and finalization receipts with predecessor/replacement and source-receipt binding.
- Added strict event schema validation, signing-key cutoff checks, terminal revocation handling, and idempotent recovery paths.
- Integrated Batch 289 events into independent checkpoint inventory and overall recovery-gate convergence.
- Added owner-scoped prepare/apply/audit/snapshot/reconcile application APIs and HTTP routes.
- Added focused regression coverage for empty-history safety, invalid challenge inputs, source-currentness gating, schema binding, checkpoint inventory, convergence, and route wiring.
