# Agentic AI V4 — Batch 244

## Purpose

Batch 244 adds signed external attestations for Batch 243 lifecycle finalization receipts. Each attestation binds the receipt and its lifecycle finalization event to the source receipt-chain prefix, source checkpoint fingerprint, lifecycle audit digest, source signing-key binding, and current signing-key lifecycle binding.

## Integrity and recovery

- Only complete, current Batch 243 lifecycle receipt history can be attested; unhealthy, pending, orphaned, or incomplete source histories fail closed.
- Attestations use deterministic operation IDs and an append-only signed ledger.
- The binding covers receipt ID/digest/generation, lifecycle finalization event, challenge/action, target/source receipt references, intent/action event digests, replacement attestation, receipt-binding digest, source receipt-chain prefix, checkpoint fingerprint, lifecycle audit digest, signing-key binding, key-cutoff state, and predecessor attestation.
- Audit verifies historical signatures, receipt/finalization binding, source prefix digest, monotonically increasing attestation generation, predecessor ID/digest, and key-cutoff state.
- Missing attestations or a non-current independent checkpoint yield `recovery_required`; invalid signatures or bindings yield `unhealthy`; a source terminal revocation remains `decision_blocked`.
- Batch 244 attestation events are included in the independent checkpoint snapshot and recovery-gate convergence audit.

## API

Owner-scoped, authenticated routes are added beneath the Batch 243 lifecycle root at `/finalization-receipts/external-attestations`:

- `POST /attest`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

## Validation scope

Focused regression validation covers Batch 102 and Batches 238–244: 27/27 tests pass against the extracted source. All JavaScript/MJS/CJS files pass `node --check`; the Batch 102 import test reports no missing relative imports. The full cumulative `npm test` suite is not claimed as passed because it has not been run to a final passing summary in this stage.

## GitHub

No commit performed.
