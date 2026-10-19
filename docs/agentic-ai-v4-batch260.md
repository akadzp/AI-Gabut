# Agentic AI V4 — Batch 260

Batch 260 externally attests Batch 259 lifecycle finalization receipts. Each attestation binds the source receipt ID, digest, and generation to its lifecycle finalization event, challenge/action, target/source attestation, intent/action events, optional replacement attestation, receipt-binding digest, receipt-chain prefix digest, checkpoint fingerprint, lifecycle audit digest, signing-key lifecycle bindings, key-cutoff flags, and predecessor attestation.

The writer requires a healthy ledger, a complete and current Batch 259 lifecycle receipt chain, a valid finalization event for each receipt, and a current independent checkpoint when checkpointing is enabled. It reuses an existing attestation only when the binding and current signing-key lifecycle match. Otherwise it appends a new signed event with a deterministic operation ID and a predecessor link.

The auditor verifies historical signatures, receipt/source bindings, monotonic attestation generations, predecessor continuity, prefix digests, key-cutoff state, checkpoint state, and terminal revocation. Missing attestations require recovery; invalid bindings or signatures produce an unhealthy state. Terminal source revocation remains decision-blocking.

Owner-scoped application methods and HTTP routes expose attest, audit, snapshot, and reconcile operations. Batch 260 status and generation-binding digest participate in overall recovery-gate convergence and the independent checkpoint snapshot.
