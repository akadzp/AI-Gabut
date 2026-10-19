# Agentic AI V4 — Batch 261 Roadmap

## Renewal/Revocation Lifecycle for Batch 260 External Attestations

Batch 261 extends the cumulative Batch 260 source with a signed lifecycle for Batch 260 external attestations.

- Signed intent, renewal, revocation, supersession, finalization, and finalization-receipt events.
- Monotonic generation and predecessor/replacement continuity.
- Source receipt, lifecycle finalization, signing-key cutoff, and independent checkpoint binding.
- Replay-safe operation IDs and owner-scoped challenge/apply APIs.
- Recovery reconciliation for interrupted lifecycle phases and missing receipts.
- Terminal revocation prevents descendant renewal.
- Application API and authenticated HTTP routes.
- Independent checkpoint snapshots include Batch 261 events.

## Validation

Focused Batch 261 tests, Batch 259/260 regression tests, syntax checks, relative import checks, ZIP integrity, and extracted-source SHA-256 comparisons are required. Full cumulative test completion is reported separately and is not inferred from focused tests.
