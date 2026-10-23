# Agentic AI V4 — Batch 285

Batch 285 implements renewal and revocation lifecycle management for Batch 284 external attestations.

## Lifecycle

- `BATCH285_INTENT_EVENT`
- `BATCH285_RENEWED_EVENT`
- `BATCH285_REVOKED_EVENT`
- `BATCH285_SUPERSEDED_EVENT`
- `BATCH285_FINALIZED_EVENT`
- `BATCH285_RECEIPT_EVENT`

Renewal follows intent → renewed → superseded → finalized → finalization receipt. Revocation follows intent → revoked → finalized → finalization receipt. Terminal revocation blocks descendants and later renewal attempts. Each event is signed and bound to the challenge, lifecycle generation, target attestation, source receipt, key lifecycle, and checkpoint fingerprint.

## API surface

The owner-scoped HTTP root is derived from the Batch 284 external-attestation root with `/lifecycle`, exposing `prepare`, `apply`, `audit`, `snapshot`, and `reconcile` routes.

## Recovery and validation

Reconciliation checks the Batch 284 external-attestation source, resumes pending lifecycle challenges, advances independent checkpoints, and re-audits the finalization receipt chain. See `BATCH285_VALIDATION_REPORT.md` for the exact test results and limitations.
