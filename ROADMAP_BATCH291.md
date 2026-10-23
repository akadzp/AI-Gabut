# Roadmap — Batch 291

## Delivered

- Renewal and revocation lifecycle for Batch 290 external attestations.
- Signed append-only lifecycle phases with predecessor/replacement binding.
- Finalization receipts with receipt-chain continuity and terminal revocation handling.
- Signing-key lifecycle and key-cutoff revalidation.
- Independent checkpoint inventory, recovery, and overall recovery-gate convergence integration.
- Owner-scoped application APIs and HTTP routes.

## Remaining verification

- Run the complete cumulative `npm test` suite to a final TAP summary in an environment with sufficient time.
- Exercise positive end-to-end renewal and revocation using a fully current Batch 290 external-attestation chain and enabled checkpoint.
- Start the HTTP listener with installed dependencies and exercise all five Batch 291 routes.

## Next planned stage

Batch 293 — Renewal/Revocation Lifecycle for Batch 292 External Attestations, Cross-Generation Supersession, and Finalization Receipt Recovery.
