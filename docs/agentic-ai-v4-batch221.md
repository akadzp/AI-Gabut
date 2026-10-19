# Agentic AI V4 — Batch 221

## Finalization-Receipt Binding-Attestation Lifecycle Receipts, Independent Supersession Checkpointing, and Key-Cutoff Recovery Continuity

Batch 221 adds a signed receipt for every finalized finalization-receipt checkpoint binding attestation. The receipt binds the attestation generation to its signed supersession event and predecessor receipt chain.

### Changes

- Added the signed append-only event `proof_continuity_finalization_receipt_checkpoint_binding_attestation_lifecycle_receipt_finalized`.
- Receipt generation follows the binding-attestation generation monotonically. Generation 1 has no predecessor; each later generation must reference the immediately preceding receipt ID and digest.
- Generation N receipts require the matching signed supersession event when the attestation has a predecessor. The receipt binds the supersession ID and digest, replacement attestation ID and digest, binding digest, action, and key-cutoff marker.
- Receipt creation is idempotent by deterministic operation ID and refuses stale attestations, out-of-order generations, missing supersession, predecessor gaps, and key-lifecycle mismatch.
- Added an independent external checkpoint domain, `cross_domain_finalization_receipt_binding_attestation_lifecycle_receipts`, whose snapshot contains only the lifecycle receipt events. Provider and endpoint reuse is a hard blocker.
- Integrated the checkpoint into the shared finalization checkpoint advancement/reconciliation loop and recovery-gate convergence digest.
- Recovery resumes when the local receipt committed but the external checkpoint write failed. Retry reuses the same receipt and advances the lagging checkpoint without duplicating the receipt.
- Key-cutoff evidence is preserved in the supersession event and receipt. A receipt does not restore eligibility by itself; the current attestation, its supersession chain, signing-key binding, and all required checkpoints must also be current.

### API

- `GET /api/.../recovery-gate-proof-continuity/finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/checkpoint/status`
- `GET /api/.../recovery-gate-proof-continuity/finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/checkpoint/audit`
- `POST /api/.../recovery-gate-proof-continuity/finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/checkpoint/enrollment/prepare`
- `POST /api/.../recovery-gate-proof-continuity/finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/checkpoint/enrollment/apply`
- `POST /api/.../recovery-gate-proof-continuity/finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/checkpoint/reconcile`

### Configuration

- `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_RECEIPT_ANCHOR_URL`
- `AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_RECEIPT_ANCHOR_TOKEN`
- `AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_RECEIPT_ANCHOR=true`

The independent checkpoint is opt-in for backward compatibility. When enabled or required, it must be enrolled before it can provide current-decision evidence.

### Regression coverage

- `tests/apps/agentic-recovery-slo-v4-batch221-receipts.mjs`
  - Signed receipt chain, supersession binding, and operation replay.
  - Recovery after local receipt commit and external checkpoint write failure.
  - Key-cutoff continuity across renewal and receipt generation.
  - Provider/endpoint reuse rejection and API route registration.

### Recovery semantics

- The receipt ledger is append-only; receipts are not overwritten or deleted.
- A valid historical signature does not imply current-decision eligibility.
- A missing receipt for the latest attestation is `recovery_required`.
- A broken predecessor, duplicate receipt, invalid signature, or supersession mismatch is `unhealthy`.
- If the external receipt checkpoint is behind local state, convergence remains blocked until reconciliation succeeds.
- Revocation and key-cutoff blockers in upstream evidence remain authoritative.
