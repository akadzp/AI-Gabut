# Batch 313 Validation Report

## Scope

Validated the cumulative Agentic AI V4 source from Batch 312 with Batch 313 renewal/revocation lifecycle changes for Batch 312 external attestations.

## Regression tests

The focused regression run completed with a final TAP summary:

- Total selected tests: 47
- Passed: 47
- Failed: 0
- Cancelled/skipped/todo: 0

Coverage included Batch 102 application/import/API checks, artifact persistence, Batch 104 durable execution leases, Batch 309 lifecycle, Batch 310 external attestation, Batch 311 lifecycle, Batch 312 external attestation, and six Batch 313 lifecycle tests.

The cumulative `npm test` suite was not run to a final TAP summary and is not claimed as passing.

## Syntax and configuration

- JavaScript/MJS/CJS files: 405/405 passed `node --check`.
- JSON files: 1/1 parsed successfully.
- Relative import resolution and top-level server API references passed the Batch 102 regression checks.

## Archive verification

The release ZIP was checked with `zip -T` and `unzip -t`. It was extracted into a clean directory; file inventory and SHA-256 checksums were compared between the packaged source and extracted source. The focused regression suite and syntax checks were repeated against the extracted source.

## Remaining verification gaps

- Positive end-to-end provisioning of a verified-current Batch 312 attestation chain through Batch 313 renewal/revocation and finalization receipt.
- Crash-injection at every lifecycle and checkpoint boundary.
- Live HTTP listener startup with runtime dependencies installed.
- Full cumulative `npm test` with a final TAP summary.

No GitHub commit was made.
