# Agentic AI V4 — Batch 315 Status

## Scope
Batch 315 adds a signed renewal/revocation lifecycle for Batch 314 external attestations, including cross-generation supersession, append-only finalization receipts, key-cutoff checks, replay protection, independent checkpoint recovery, and overall recovery-gate convergence.

## State
- Implementation: complete
- Source API and owner-scoped HTTP routes: added
- Ledger event allowlist and schema validation: updated
- Independent checkpoint inventory: includes Batch 315 lifecycle events and receipts
- Focused regression tests: 57/57 passed across isolated test runs
- Full cumulative `npm test`: not run to completion
- GitHub commit: none

## Lifecycle
`Intent → Renewed/Revoked → Superseded (renewal only) → Finalized → Finalization Receipt`

Renewal requires the current Batch 314 external attestation and binds the replacement to its predecessor. Revocation is terminal. Recovery reuses durable phases, checks source receipts and checkpoint state, and blocks current-decision usability when evidence is missing, stale, or invalid.
