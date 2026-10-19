# Batch 271 Validation Report

## Scope

Validation was performed on the cumulative Batch 270 source with Batch 271 lifecycle changes.

## Focused regression results

- **31/31 tests passed** across Batch 102 application/API/dependency checks, artifact tests, and Batch 267–271 regression suites.
- Batch 271-specific tests: **3/3 passed**.
- The Batch 102 relative-import check passed and confirmed that relative JavaScript imports resolve within the source archive.
- The Batch 102 server API reference check passed.

## Syntax and configuration

- JavaScript/MJS/CJS syntax checks: **363/363 passed**.
- JSON files parsed: **1/1 passed**.

## Cumulative test suite limitation

`npm test` was attempted with a 300-second execution limit. The run reached subtest 1129 (Batch 169) without a visible `not ok` result in the captured output, then timed out before producing a final TAP summary. Therefore the cumulative full suite is **not claimed as passed**. The Batch 170 suite and the combined Batch 267–271 targeted selection were also run separately from the full suite; all selected tests passed.

## End-to-end limitations

- A positive end-to-end chain that first constructs a current Batch 270 attestation and then exercises the complete Batch 271 renew/revoke/finalization/checkpoint-recovery path was not completed.
- Direct HTTP listener startup was not independently exercised; route registration and application API wiring were checked by the regression suite.

## Archive validation

The final ZIP was tested with `zip -T` and `unzip -t`. The extracted archive was compared file-by-file against the staged source using SHA-256, and the focused regression and syntax checks were repeated on the extracted copy. Exact final file/entry counts, ZIP size, and archive SHA-256 are recorded in the delivery summary.

## Repository policy

No GitHub commit was made.
