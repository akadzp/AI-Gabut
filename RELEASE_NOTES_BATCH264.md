# Agentic AI V4 — Batch 264 Release Notes

## Scope
Batch 264 adds external attestations for Batch 263 lifecycle finalization receipts, including receipt-chain continuity, signing-key lifecycle binding, predecessor continuity, and independent checkpoint recovery integration.

## Changes
- Added signed append-only event `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch263_lifecycle_finalization_receipt_external_attested`.
- Added deterministic receipt-bound attestation creation with idempotent reuse and predecessor linking.
- Added source receipt, finalization event, receipt-prefix, lifecycle audit, checkpoint, and key-binding validation.
- Added audit, snapshot, and reconciliation APIs and owner-scoped HTTP routes.
- Integrated Batch 264 audit status into overall recovery-gate convergence and usability decisions.
- Extended the independent checkpoint snapshot to include Batch 264 events.
- Added three focused regression tests for empty history, API/checkpoint integration, and ledger binding validation.

## Validation boundaries
Focused regression tests and static/archive checks are run against the extracted release ZIP. Full cumulative `npm test` and a positive end-to-end run using persisted, current Batch 263 receipts are not claimed unless separately completed.

No GitHub commit is performed by this release workflow.
