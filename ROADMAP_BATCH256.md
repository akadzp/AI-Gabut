# Agentic AI V4 — Roadmap Batch 256

## Scope
External attestation for Batch 255 lifecycle finalization receipts, cross-generation receipt continuity, signing-key cutoff tracking, and independent checkpoint recovery.

## Deliverables
- Signed Batch 256 external-attestation event bound to each Batch 255 lifecycle finalization receipt.
- Receipt-prefix continuity and predecessor-attestation chain validation.
- Idempotent reconciliation that does not fabricate receipts or rewrite source history.
- Signing-key lifecycle cutoff/revalidation evidence.
- Independent checkpoint snapshot inclusion and checkpoint advancement before/after attestation.
- Owner-scoped application API and HTTP routes.
- Regression tests for empty history, source gating, checkpoint integration, and event-type consistency.

## Acceptance criteria
- Empty history remains read-only and returns `not_initialized`.
- Missing source receipts or non-current source audit prevents attestation issuance.
- Missing attestations are reported as `recovery_required`.
- Invalid signature, receipt binding, predecessor chain, or prefix digest is reported as `unhealthy`.
- Terminal source revocation remains `decision_blocked` and cannot be reactivated by external attestation.
- Syntax, import, focused regression, and ZIP integrity checks pass on the extracted archive.

## Next stage
Batch 257: Renewal/revocation lifecycle for Batch 256 external attestations, with cross-generation supersession and finalization receipt recovery.
