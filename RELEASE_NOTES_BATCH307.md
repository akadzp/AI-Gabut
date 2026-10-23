# Release Notes — Agentic AI V4 Batch 307

## Summary
Batch 307 adds a lifecycle for Batch 306 external attestations, including renewal, terminal revocation, supersession, finalization receipts, checkpoint-aware recovery, and overall recovery-gate convergence.

## API
Added owner-scoped routes beneath `/finalization-receipts/external-attestations/lifecycle/lifecycle`:
- `POST /prepare`
- `POST /apply`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

## Safety and recovery
- Only `renew` and `revoke` actions are accepted.
- Challenges bind the active Batch 306 attestation, source receipt, generation, ledger snapshot, and signing-key lifecycle binding.
- A finalized revocation is terminal; later renewal descendants are rejected by audit.
- Missing or incomplete finalization receipts require recovery; invalid bindings or signatures fail closed.
- Empty history remains read-only and does not fabricate lifecycle events or receipts.

## Validation note
Focused regression tests and source/archive checks passed. The full cumulative test suite and positive end-to-end execution over a fully provisioned source chain are not claimed as complete.
