# Release Notes — Batch 321

## Scope

Batch 321 implements a lifecycle layer over Batch 320 external attestations.

- Renewal and terminal revocation operations use owner-scoped, expiring confirmation challenges.
- Append-only lifecycle events bind target attestation identity/digest/generation, source Batch 319 finalization receipt, reason digest, signing-key lifecycle binding, and checkpoint state.
- Renewal creates a replacement attestation and explicit predecessor/supersession linkage.
- Finalization receipts bind the lifecycle finalization event, audit digest, source checkpoint fingerprint, signing-key binding, and predecessor receipt.
- Recovery can resume pending lifecycle phases and reconcile checkpoint state without fabricating missing source attestations or receipts.
- Audit results participate in overall recovery-gate convergence and owner-scoped HTTP routes are provided for prepare, apply, audit, snapshot, and reconcile.

## Safety behavior

- Unsupported actions and invalid challenge parameters are rejected before mutation.
- Lifecycle mutation requires a `verified_current` Batch 320 external-attestation source.
- Terminal revocation blocks reactivation through this lifecycle.
- Invalid signatures, broken predecessor links, mismatched binding digests, or invalid receipt chains fail closed.

## Validation

See `BATCH321_VALIDATION_REPORT.md` for the exact regression set and known validation limits.
