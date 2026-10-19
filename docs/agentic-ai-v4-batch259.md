# Agentic AI V4 — Batch 259

## Scope
Renewal/revocation lifecycle for Batch 258 external attestations, cross-generation supersession, finalization receipt recovery, and independent checkpoint convergence.

## Lifecycle
`Intent → Renewed/Revoked → Superseded (renewal only) → Finalized → Finalization Receipt`.

## Controls
- Owner-scoped prepare/apply/audit/snapshot/reconcile APIs.
- Signed append-only lifecycle events and deterministic operation IDs.
- Current Batch 258 external-attestation source validation before mutation.
- Monotonic lifecycle generations and predecessor/replacement bindings.
- Terminal revocation blocks subsequent renewal.
- Finalization receipts bind action, target, source receipt, key lifecycle, and checkpoint evidence.
- Recovery resumes pending phases and reconciles independent checkpoints before reporting current status.

## Validation
See `BATCH259_VALIDATION_REPORT.md` for focused regression, syntax, import, and archive-integrity results. Full cumulative test-suite status is reported separately and must not be inferred from focused tests.
