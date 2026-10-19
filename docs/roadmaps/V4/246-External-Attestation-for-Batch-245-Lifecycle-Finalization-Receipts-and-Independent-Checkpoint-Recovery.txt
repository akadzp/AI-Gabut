# Agentic AI V4 — Batch 246

## Purpose

Batch 246 adds signed external attestations for Batch 245 lifecycle finalization receipts. It preserves the cumulative Batch 245 source and adds receipt-to-attestation binding, cross-generation attestation continuity, checkpoint-aware reconciliation, and owner-scoped API access.

## Integrity and recovery

- Each Batch 245 lifecycle finalization receipt is eligible for an external attestation only when the source lifecycle audit is complete and non-unhealthy.
- The attestation binds the finalization receipt ID/digest/generation, lifecycle finalization event, challenge/action, target and replacement attestation references, intent/action event references, receipt binding digest, receipt-chain prefix digest, checkpoint fingerprint, lifecycle audit digest, source/current signing-key lifecycle bindings, and key-cutoff flags.
- Attestations are signed append-only events with deterministic operation IDs.
- Audit verifies historical signatures, receipt existence, finalization event linkage, receipt-prefix digest, stable binding digest, generation ordering, predecessor ID/digest continuity, key-cutoff consistency, and the presence of an attestation for every receipt.
- Missing attestations or a non-current independent checkpoint yield `recovery_required`; invalid signatures or bindings yield `unhealthy`; terminal source revocation remains `decision_blocked`.
- Reconciliation first resumes the Batch 245 lifecycle and receipt chain, then creates or reuses external attestations, advances the independent checkpoint, and audits the result.
- Batch 246 events are accepted by the continuity ledger, included in the independent checkpoint snapshot, and incorporated into overall recovery-gate convergence.

## API

Owner-scoped authenticated endpoints are added under `/finalization-receipts/external-attestations` nested below the Batch 245 lifecycle root:

- `POST /attest`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

## Validation scope

Focused tests verify empty-history fail-closed behavior, no fabricated attestations, snapshot domain, application API wiring, checkpoint snapshot inclusion, overall recovery-gate convergence, and route registration. The full cumulative suite and a positive end-to-end run that first constructs every prerequisite lifecycle receipt are not claimed as passing unless they produce a final successful summary.

## GitHub

No commit performed.
