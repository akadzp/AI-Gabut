# Roadmap — Agentic AI V4 Batch 299

## Completed in this stage
- Renewal/revocation lifecycle for Batch 298 external attestations.
- Cross-generation supersession and terminal revocation checks.
- Finalization receipt recovery and checkpoint-gate integration.
- Owner-scoped API wiring and focused regression coverage.

## Next stage: Batch 300
- Externally attest Batch 299 lifecycle finalization receipts.
- Bind attestations to receipt digests, lifecycle finalization events, chain-prefix digests, checkpoint fingerprints, and signing-key lifecycle.
- Validate predecessor continuity and key-cutoff recovery.
- Reconcile checkpoint advancement before and after attestation creation.
- Add focused regression coverage and revalidate the complete extracted source archive.

## Remaining validation work
- Execute the full cumulative test suite to a final TAP summary.
- Exercise a positive end-to-end renewal and terminal-revocation flow with a fully current upstream attestation chain.
- Start the HTTP listener in an environment with declared runtime dependencies installed.
