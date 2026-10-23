# Batch 277 Validation Report

## Scope
Cumulative Agentic AI V4 source based on Batch 276, with Batch 277 renewal/revocation lifecycle for Batch 276 external attestations.

## Focused regression results

The following selected regression files were executed together against the Batch 277 source tree:

- Batch 102 application entrypoint/dependency/API checks: 13 tests passed.
- Artifact tests: 3 tests passed.
- Batch 104 durable execution lease tests: 7 tests passed.
- Batch 270–277 lifecycle/attestation tests: 24 tests passed.

**Total: 47 tests passed, 0 failed.**

The Batch 277 tests cover empty-history behavior, rejection when the Batch 276 source is not current, owner-scoped API wiring, checkpoint snapshot coverage, and lifecycle event schema validation.

## Syntax and configuration

- JavaScript/MJS/CJS files checked with `node --check`: 369 passed, 0 failed.
- JSON files parsed: 1 passed, 0 failed.
- Batch 102 import-resolution and application API reference checks passed.

## Limitations

- The full cumulative `npm test` suite was not run to completion; this report does not claim full-suite success.
- A complete positive end-to-end chain that creates a current Batch 276 attestation, performs Batch 277 renewal/revocation, finalizes receipts, and validates independent checkpoint recovery was not exercised in this run.
- The HTTP listener was not started because Express is not installed in the validation runtime; the dependency declaration and application API references passed the Batch 102 checks.

ZIP integrity, extraction parity, and regression tests against the extracted final archive are validated separately after archive creation.

## Final ZIP verification

After packaging the complete source tree:

- Source/project files: 814.
- ZIP entries (including directory entries): 833.
- `zip -T`: PASS.
- `unzip -t`: PASS; no compressed-data errors.
- Extracted file parity: 814 source files, 0 missing, 0 extra, 0 SHA-256 mismatches.
- Focused regression suite re-run from the extracted final archive: 47/47 PASS.
- Syntax checks re-run from the extracted final archive: 369/369 PASS.
- JSON validation after extraction: 1/1 PASS.
