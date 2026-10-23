# Roadmap — Batch 325

## Delivered
- Renewal/revocation lifecycle for Batch 324 external attestations.
- Cross-generation predecessor/replacement integrity.
- Finalization receipts and receipt-chain recovery.
- Independent checkpoint and overall recovery-gate convergence.
- Owner-scoped API/HTTP routes and regression tests.

## Follow-up validation
- Run the complete cumulative `npm test` to a final TAP summary.
- Execute a fully provisioned positive end-to-end renewal and revocation flow.
- Run crash injection at each lifecycle and checkpoint boundary.
- Start the HTTP server with all runtime dependencies installed and verify route authorization.
