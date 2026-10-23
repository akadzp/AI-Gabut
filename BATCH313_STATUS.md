# Batch 313 Status

Status: implemented; focused regression validation passed.

- Scope: renewal/revocation lifecycle for Batch 312 external attestations.
- Added signed intent/action/supersession/finalization/receipt events with cross-generation binding and terminal-revocation enforcement.
- Added current-source gating against Batch 312 external attestations, signing-key lifecycle checks, deterministic phase operation IDs, recovery/resume logic, independent checkpoint inventory, owner-scoped routes, and overall recovery-gate convergence.
- Focused regression run: 47 tests passed across Batch 102, artifact persistence, Batch 104, and Batches 309–313 when run together.
- Batch 313 tests: 6/6 passed.
- Syntax and JSON checks are recorded in `BATCH313_VALIDATION_REPORT.md`.
- Full cumulative `npm test` is not claimed as passing unless a complete TAP summary is produced.
- Positive end-to-end provisioning of a verified-current Batch 312 attestation chain, crash-injection across every lifecycle/checkpoint boundary, and live HTTP listener startup with runtime dependencies installed remain unverified.
- GitHub: no commit made.
