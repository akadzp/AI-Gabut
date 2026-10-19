# Agentic AI V4 — Batch 255 Release Notes

## Scope

Batch 255 adds the renewal/revocation lifecycle for Batch 254 external attestations, including cross-generation supersession, signed lifecycle finalization receipts, checkpoint-aware recovery, and owner-scoped application/HTTP APIs.

## Lifecycle events

- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch254_external_attestation_lifecycle_intent`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch254_external_attestation_lifecycle_renewed`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch254_external_attestation_lifecycle_revoked`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch254_external_attestation_lifecycle_superseded`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch254_external_attestation_lifecycle_finalized`
- `proof_continuity_finalization_receipt_binding_attestation_lifecycle_batch254_external_attestation_lifecycle_finalization_receipt_finalized`

The lifecycle is append-only. Renewal preserves the predecessor chain; finalized revocation is terminal. Receipt recovery and independent checkpoint reconciliation fail closed when source attestation, signature, key binding, or chain continuity cannot be established.

## API

The application exposes prepare, apply, audit, snapshot, and reconcile operations. HTTP routes are registered beneath the Batch 254 external-attestation lifecycle root and retain application authentication and owner scoping.

## Validation

Focused regression coverage includes Batch 250–255, Batch 102 application-entrypoint/dependency checks, and artifact tests. The full cumulative test suite has not been certified as passing in this release.
