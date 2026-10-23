# Agentic AI V4 — Batch 299

Batch 299 manages renewal and terminal revocation of Batch 298 external attestations.

## Lifecycle

Renewal follows `intent → renewed → superseded → finalized → finalization receipt`. Revocation follows `intent → revoked → finalized → finalization receipt`. Each phase is appended to the continuity ledger and bound to the same challenge and lifecycle generation.

## Source and binding requirements

Mutation requires a healthy ledger, a `verified_current` Batch 298 source audit, an acceptable current lifecycle audit, a current independent checkpoint when enabled, and a valid signing-key lifecycle binding. Lifecycle bindings include the target attestation and source receipt identifiers/digests, reason digest, key-cutoff state, intent/action event references, and predecessor/replacement references where applicable.

## Recovery and audit

Operations use deterministic phase operation IDs and can resume after interruption. Audit checks signatures, generation continuity, phase ordering, predecessor/replacement links, receipt-to-finalization binding, receipt predecessor continuity, source receipt existence, checkpoint currency, and terminal revocation. A finalized revocation blocks subsequent descendants.

## API

Under `batch299ExternalAttestationLifecycleRoot` (the Batch 298 external-attestation root with the `/lifecycle` suffix):
- `POST /prepare`
- `POST /apply`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

All routes use the existing authenticated application context and owner identity.

## Validation
See `BATCH299_VALIDATION_REPORT.md`. Focused tests passed; full cumulative test-suite completion and a fully provisioned positive end-to-end lifecycle run remain unverified.
