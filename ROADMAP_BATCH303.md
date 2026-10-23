# Roadmap — Agentic AI V4 Batch 303

## Completed in this stage
- Renewal/revocation lifecycle for Batch 302 external attestations.
- Signed intent/action/finalization events and cross-generation supersession.
- Terminal revocation and replay protection.
- Finalization receipt chain with predecessor binding and recovery support.
- Independent checkpoint inventory and checkpoint-aware reconciliation.
- Owner-scoped API routes, overall recovery-gate convergence, and focused regression tests.

## Remaining validation work
- Full cumulative `npm test` to a final TAP summary.
- Positive end-to-end renewal and revocation using a fully provisioned current Batch 302 attestation chain.
- Live HTTP listener startup with runtime dependencies installed.
