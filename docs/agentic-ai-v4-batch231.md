# Agentic AI V4 — Batch 231

## External-attestation lifecycle finalization receipts and revocation-descendant enforcement

Batch 231 adds a signed append-only finalization receipt for every finalized Batch 230 external-attestation lifecycle operation. Each receipt binds the lifecycle finalization event and digest, challenge, action, target and replacement attestation references, intent/action events, lifecycle audit digest, source checkpoint fingerprint, signing-key lifecycle binding, key-cutoff evidence, and a predecessor receipt.

### Receipt continuity and recovery replay

Finalization receipts are assigned a monotonic generation and linked by predecessor ID/digest. Receipt creation uses a deterministic operation ID derived from the finalized lifecycle event. The lifecycle apply path creates the receipt immediately after finalization; an idempotent retry repairs the narrow crash window where finalization was persisted but its receipt was not. Reconciliation walks finalized lifecycle events in order and refuses to append around a missing predecessor when a later receipt already exists.

### Audit enforcement

The lifecycle audit verifies receipt signatures, generation order, predecessor continuity, receipt binding digest, lifecycle event references, key binding, and lifecycle audit digest. Missing receipts return `recovery_required`; malformed, duplicate, or misbound receipts return `unhealthy`.

Terminal revocation is detected across all finalized lifecycle events, not only the latest one. Any later Batch 229 attestation or Batch 230 lifecycle event after a finalized revocation is reported as a revocation descendant and makes the chain `unhealthy`. A valid terminal revocation remains `decision_blocked`.

### Independent checkpoint coverage

Both the lifecycle snapshot and the external-attestation checkpoint snapshot include Batch 231 receipt records. The existing lifecycle reconciliation endpoint repairs missing local receipts first, then reconciles the configured independent checkpoint, and finally returns a fresh audit. No new provider or credential is assumed.

### Validation

- Batch 231 empty-history and route/service wiring tests are included.
- A passing empty-history test proves reconciliation does not invent a receipt without a finalized lifecycle event.
- Full positive end-to-end renewal/revocation remains dependent on the cumulative integration bootstrap and is not claimed solely from structural tests.

## Validation record

- Focused regression group for Batches 223–231: 20/20 PASS after the source tree was extracted from the final ZIP.
- JavaScript/MJS/CJS syntax: 323/323 PASS.
- Relative import references: 621 checked, 0 missing.
- `package.json` JSON parse: PASS.
- Archive checks (`zip -T`, `unzip -t`) and post-extraction SHA-256 comparison are required before delivery.
- The cumulative Batch 222 integration test did not finish within a 240-second execution limit; it is not reported as passing. Positive end-to-end Batch 230 renewal/revocation remains unverified.
- HTTP listener startup and full cumulative `npm test` are not claimed as passing.
