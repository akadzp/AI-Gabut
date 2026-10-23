# Batch 287 Roadmap

## Scope

Renewal/revocation lifecycle for Batch 286 external attestations, cross-generation supersession, and finalization-receipt recovery.

## Implemented

- Signed lifecycle intent, renewal, revocation, supersession, finalization, and receipt events.
- Source attestation and Batch 285 finalization receipt binding.
- Deterministic operation IDs and idempotent phase resumption.
- Key-cutoff detection and revalidation binding.
- Independent checkpoint inventory and checkpoint advancement in application reconciliation.
- Fail-closed audit for malformed phases, invalid signatures, missing/duplicate receipts, broken predecessor chains, and terminal revocation descendants.
- Owner-scoped APIs, HTTP routes, global recovery-gate convergence, and focused tests.

## Follow-up validation

- Exercise a positive end-to-end renewal and a terminal-revocation flow using a fully verified-current Batch 286 external-attestation chain.
- Run the cumulative test suite to a final TAP summary.
- Run an HTTP listener smoke test in an environment with Express installed.
