# Agentic AI V4 — Batch 272

## Scope

Batch 272 adds signed external attestations for Batch 271 lifecycle finalization receipts. It preserves the cumulative Batch 271 source and adds receipt-to-attestation binding, cross-generation attestation continuity, signing-key lifecycle checks, independent checkpoint coverage, and recovery-gate convergence.

## Evidence binding

Each Batch 272 attestation binds the source Batch 271 finalization receipt ID, digest, generation, lifecycle finalization event ID/digest, challenge/action, target and source attestations/receipts, intent/action event digests, optional replacement attestation, receipt-binding digest, receipt-chain prefix digest, source checkpoint fingerprint, lifecycle audit digest, source/current signing-key lifecycle digests, key-cutoff flags, attestation generation, and predecessor attestation ID/digest.

## Invariants

- No attestation is fabricated when the source receipt history is empty.
- Every source receipt must resolve to its matching Batch 271 finalization event and valid receipt binding.
- Attestation generations increase monotonically and each attestation links to its predecessor by ID and digest.
- Repeated operations reuse an attestation only when the complete current binding, signature, and key lifecycle match.
- A missing attestation or stale independent checkpoint requires recovery; invalid signature or binding is unhealthy.
- A verified terminal revocation remains `decision_blocked` and is never reactivated by external attestation.
- Attestation mutation is owner-scoped and checkpoint-aware; the global recovery gate includes Batch 272 status and binding digest.

## API

The route root is derived from Batch 271:

`/finalization-receipts/external-attestations/lifecycle/finalization-receipts/external-attestations`

- `POST /attest`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

The application boundary advances the independent checkpoint before attestation and again after a persisted attestation, then re-audits the chain.

## Validation scope

See `BATCH272_VALIDATION_REPORT.md`. Focused regression tests and syntax/archive checks are recorded separately from the full cumulative test suite. No GitHub commit was made.
