# Agentic AI V4 — Batch 312

Batch 312 adds external attestation for Batch 311 lifecycle finalization receipts. It stores an append-only attestation event with a deterministic operation ID and a binding digest over the receipt identity, finalization event, action metadata, receipt-chain prefix, checkpoint fingerprint, lifecycle audit digest, and signing-key lifecycle binding.

Auditing verifies historical signature validity, source receipt/finalization correspondence, predecessor attestation continuity, binding digest integrity, key-cutoff state, and independent checkpoint currency. Missing attestations produce `recovery_required`; malformed bindings or invalid signatures produce `unhealthy`; a source terminal revocation remains `decision_blocked`.

The application exposes owner-scoped attest, audit, snapshot, and reconcile routes under the Batch 311 lifecycle root. Reconciliation advances the independent checkpoint before and after attestation when source receipts exist, then audits the final convergence state.

This batch passed its focused regression suite and static/archive checks. It is not a claim that the full cumulative test suite or live HTTP startup has passed.
