# Roadmap — Batch 309

## Delivered
- Batch 309 lifecycle for Batch 308 external attestations.
- Renewal and terminal revocation event flow.
- Cross-generation predecessor/replacement validation.
- Finalization receipt binding and recovery.
- Independent checkpoint inventory and overall convergence integration.
- Owner-scoped HTTP routes and regression tests.

## Follow-up work
- Run the complete cumulative `npm test` suite to a final TAP summary.
- Exercise a positive end-to-end renewal and terminal revocation with a fully provisioned verified-current Batch 308 chain.
- Exercise crash injection between every lifecycle phase and checkpoint advancement.
- Validate HTTP listener startup with runtime dependencies installed.
