# Agentic AI V4 — Batch 293

Batch 293 implements the renewal/revocation lifecycle for Batch 292 external attestations.

## Lifecycle

The signed append-only ledger records intent, renewed/revoked action, supersession when renewing, finalization, and a finalization receipt. Each event binds the challenge, lifecycle generation, target Batch 292 attestation, source Batch 291 finalization receipt, reason digest, signing-key lifecycle binding, and checkpoint context. Renewal links the replacement to its predecessor. Revocation is terminal and prevents later lifecycle descendants from being treated as current.

## Recovery and audit

The service uses deterministic operation IDs for idempotent resume. Audit checks lifecycle phase consistency, event signatures and bindings, generation monotonicity, replacement/predecessor links, finalization receipt coverage and receipt-chain continuity, key-cutoff revalidation, source Batch 292 attestation state, and independent checkpoint freshness. Missing receipts can be resumed only from a valid persisted finalization event; invalid bindings fail closed.

Reconciliation first brings Batch 292 external-attestation receipt coverage current, then reconciles Batch 293 lifecycle phases and checkpoint state, and finally reruns the lifecycle audit. Batch 293 events are included in ledger schema validation and the independent checkpoint inventory.

## Application surface

Owner-scoped authenticated routes are registered beneath the Batch 292 external-attestation root with `/lifecycle/prepare`, `/lifecycle/apply`, `/lifecycle/audit`, `/lifecycle/snapshot`, and `/lifecycle/reconcile` suffixes. Overall recovery-gate convergence incorporates Batch 293 status and generation-binding digest.

## Verification boundaries

The focused/adjacent tests passed 29/29; the separate Batch 104 durable execution lease suite passed 7/7 on this run. Syntax checks passed 385/385 and `package.json` parsed successfully. Full cumulative `npm test`, a positive end-to-end lifecycle flow using a fully verified-current Batch 292 chain and enabled independent checkpoint, and live HTTP listener startup were not claimed as passing.
