# Agentic AI V4 — Batch 276

Batch 276 adds external attestations for Batch 275 lifecycle finalization receipts. It preserves the cumulative Batch 275 source and introduces an independently audited attestation chain for each signed lifecycle finalization receipt.

## Attestation binding

Each Batch 276 event binds the source receipt ID, digest, and generation; the lifecycle finalization event ID and digest; challenge/action; target and source receipt references; intent/action event IDs and digests; optional replacement attestation; receipt-binding digest; receipt-chain prefix digest; checkpoint fingerprint; lifecycle audit digest; source/current signing-key lifecycle bindings; key-cutoff state; attestation generation; and predecessor attestation ID/digest.

The event is appended to the existing signed proof-continuity ledger. Deterministic operation IDs support safe retries. An existing attestation is reused only when the source receipt binding and current key lifecycle binding match; a changed binding produces a new chained attestation.

## Audit and recovery

The audit checks every Batch 275 finalization receipt, verifies historical signatures, validates receipt/finalization bindings and the cross-generation predecessor chain, detects missing attestations, and checks independent checkpoint currency and signing-key cutoff state. Missing attestations or a stale checkpoint require recovery; broken signatures or bindings fail closed as `unhealthy`; verified terminal revocation remains `decision_blocked`.

Reconciliation first recovers the Batch 275 lifecycle, advances the independent checkpoint before attestation when source receipts exist, creates/reuses attestations, advances the checkpoint after mutation, and performs a final audit.

## Integration

- Ledger event allow-lists and schema validation include Batch 276.
- Independent checkpoint snapshots include Batch 276 attestation events.
- Application APIs expose attest, audit, snapshot, and reconcile operations scoped to the authenticated owner.
- HTTP routes are rooted at `/finalization-receipts/external-attestations` under the Batch 275 lifecycle route hierarchy.
- Overall recovery-gate convergence includes Batch 276 status, required-state, and generation-binding digest.
- Regression tests cover empty-history safety, API/checkpoint wiring, source receipt binding, and malformed binding rejection.

No GitHub commit is made by this batch.
