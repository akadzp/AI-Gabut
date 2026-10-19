# Agentic AI V4 — Batch 220

## Finalization-Receipt Checkpoint Binding Attestation Renewal, Supersession, and Key-Cutoff Revalidation

Batch 220 extends the Batch 219 signed finalization-receipt checkpoint binding attestation with explicit, replay-safe renewal and supersession evidence.

### Changes

- Added the signed append-only event `proof_continuity_finalization_receipt_checkpoint_binding_attestation_superseded`.
- Added explicit renewal with a required `operationId`; an operation ID is bound to the current checkpoint and key-lifecycle binding and cannot be replayed against a different binding.
- Added predecessor/replacement validation, monotonic generation checks, and signed supersession events.
- Added recovery behavior for a renewal event committed locally while external checkpoint advancement fails. Retry resumes the same renewal and finalizes the missing supersession without duplicating events.
- Added key-cutoff detection when the active signing-key lifecycle binding differs from the prior attestation. A current-key renewal records the cutoff in supersession evidence and can restore current-decision eligibility only after all required checkpoints are current.
- Added strict opt-in key-cutoff enforcement through `AGENTIC_REQUIRE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_RECEIPT_CHECKPOINT_BINDING_ATTESTATION_KEY_CUTOFF_REVALIDATION=true`.
- Included supersession and key-cutoff state in the cross-domain convergence generation-binding digest.

### API

- `POST /api/.../recovery-gate-proof-continuity/finalization-receipt-checkpoint/binding-attestation/renew`
- `POST /api/.../recovery-gate-proof-continuity/finalization-receipt-checkpoint/binding-attestation/supersession/finalize`

Existing `attest` and `audit` routes remain available.

### Recovery semantics

- A renewal is bound to a stable operation ID and current checkpoint/key binding.
- A generation greater than one is not current until its supersession event is signed and checkpoint advancement succeeds.
- Key rotation makes the prior binding attestation stale; the old attestation remains historical evidence.
- A replacement attestation signed under the current key records whether it supersedes an attestation from a prior key lifecycle binding.
- External checkpoint rollback, same-sequence digest forks, invalid signatures, or broken predecessor links remain hard blockers.
- Strict key-cutoff enforcement is opt-in and blocks current-decision use until renewal revalidates the binding.

### Regression coverage

- `tests/apps/agentic-recovery-slo-v4-batch220-renewal.mjs`
- `tests/apps/agentic-recovery-slo-v4-batch220-key-cutoff.mjs`
- `tests/apps/agentic-recovery-slo-v4-batch220-recovery-routes.mjs`
