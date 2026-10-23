# Batch 278 Validation Report

## Scope
Cumulative Agentic AI V4 source based on Batch 277, adding external attestations for Batch 277 lifecycle finalization receipts, cross-generation receipt continuity, independent checkpoint recovery, and overall recovery-gate convergence.

## Focused regression results

The following selected regression files were executed together:

- Batch 102 application entrypoint, authentication, import-resolution, API-reference, and dependency checks: 13 passed.
- Artifact tests: 3 passed.
- Batch 104 durable execution lease tests: 7 passed.
- Batch 270–278 focused lifecycle/attestation tests: 27 passed.

**Total: 50 tests passed, 0 failed.**

Batch 278 tests cover empty-history behavior, source preconditions, owner-scoped application API wiring, independent checkpoint snapshot coverage, global recovery-gate integration, and malformed attestation-binding schema validation.

## Syntax and configuration

- JavaScript/MJS/CJS files checked with `node --check`: 370 passed, 0 failed.
- JSON files parsed: 1 passed, 0 failed.
- Batch 102 relative-import resolution and application API-reference checks passed.

## Limitations

- The full cumulative `npm test` suite was not run to completion; this report does not claim full-suite success.
- A complete positive end-to-end chain that creates a current Batch 277 lifecycle receipt, publishes a Batch 278 external attestation, advances the independent checkpoint, and verifies the full receipt/attestation chain was not exercised.
- The HTTP listener was not started because Express is not installed in the validation runtime. The Express dependency remains declared in `package.json`; Batch 102 API-reference and dependency-declaration tests passed.
- The optional recovery-SLO export verifier was not run because no `--bundle <file.json>` input was supplied.

## Final ZIP verification

The final cumulative ZIP is validated after packaging by:

- `zip -T` and `unzip -t`.
- Extracting into a clean directory and comparing all source-file SHA-256 hashes.
- Re-running the focused regression tests against the extracted archive.
- Re-running JavaScript syntax checks and JSON parsing against the extracted archive.

The final artifact's exact file and ZIP-entry counts are reported with the delivered archive.
