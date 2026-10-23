# Release Notes — Batch 324

## Added

- Signed external attestation events for Batch 323 lifecycle finalization receipts.
- Canonical attestation binding over receipt IDs/digests/generations, lifecycle finalization events, challenge/action references, source receipt-chain prefix, checkpoint fingerprint, lifecycle audit digest, signing-key lifecycle binding, key-cutoff state, and predecessor attestation linkage.
- Audit validation for historical signatures, receipt-to-finalization binding, generation sequence, predecessor continuity, receipt-prefix digest, missing attestations, checkpoint freshness, and terminal revocation.
- Read-only receipt/attestation snapshot and idempotent reconciliation.
- Application wrappers and owner-scoped `attest`, `audit`, `snapshot`, and `reconcile` HTTP routes.
- Batch 324 convergence status and generation-binding digest integration.
- Six focused regression tests.

## Compatibility

The cumulative event allowlist and independent checkpoint snapshot inventory now include Batch 324 attestation events. The existing Batch 322 schema regression was updated to assert the extended cumulative allowlist.

## Validation limits

Focused regression suites passed. Full cumulative `npm test`, live HTTP listener startup with production runtime dependencies, crash-injection at all phase boundaries, and a fully provisioned positive end-to-end Batch 323 receipt → Batch 324 attestation flow remain unverified.
