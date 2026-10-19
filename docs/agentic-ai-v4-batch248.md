# Agentic AI V4 — Batch 248

## Scope

Batch 248 adds signed external attestations for Batch 247 external-attestation lifecycle finalization receipts. It preserves the cumulative Batch 247 source and adds receipt-to-finalization binding, cross-generation predecessor continuity, source receipt-chain prefix verification, signing-key cutoff tracking, independent checkpoint snapshot coverage, owner-scoped application methods and HTTP routes, and recovery-gate convergence.

## Integrity and recovery rules

- Each attestation binds the Batch 247 finalization receipt, lifecycle finalization event, challenge/action, source receipt chain, lifecycle audit digest, checkpoint fingerprint, and signing-key lifecycle binding.
- Attestation generations are monotonic and each attestation binds the predecessor ID and digest.
- Missing attestations or a non-current checkpoint require recovery; invalid signatures or broken bindings fail closed as unhealthy.
- Terminal source revocation remains decision-blocked and cannot be overridden by external attestation.
- Deterministic operation IDs make retries idempotent; source receipt history is append-only.

## API

The authenticated owner-scoped routes are mounted below `/finalization-receipts/external-attestations` under the Batch 247 lifecycle path: `POST /attest`, `GET /audit`, `GET /snapshot`, and `POST /reconcile`.

## Validation

Validation results are recorded in `docs/status/Batch-248-Release-Notes.txt`. Full cumulative `npm test` is not claimed unless the entire suite completes and produces a final summary. HTTP listener startup is not claimed unless the runtime dependency is installed and startup is exercised directly. No GitHub commit is made.
