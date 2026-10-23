# Agentic AI V4 — Batch 297 Validation Report

## Scope

Batch 297 adds a signed renewal/revocation lifecycle for Batch 296 external attestations, including intent/action lineage, supersession, finalization receipts, replay protection, terminal revocation, recovery/resume, independent checkpoint advancement, and cumulative recovery-gate convergence.

## Focused regression results

The following selected regression files were run together against the final source tree:

- `tests/apps/agentic-entrypoint-dependencies-batch102.mjs`
- `tests/apps/agentic-artifacts.mjs`
- `tests/apps/agentic-durable-execution-lease-batch104.mjs`
- `tests/apps/agentic-recovery-slo-v4-batch294-external-attestation.mjs`
- `tests/apps/agentic-recovery-slo-v4-batch295-external-attestation-lifecycle.mjs`
- `tests/apps/agentic-recovery-slo-v4-batch296-external-attestation.mjs`
- `tests/apps/agentic-recovery-slo-v4-batch297-external-attestation-lifecycle.mjs`

**Result: 39/39 tests passed.** This includes 13 Batch 102 application/dependency/API tests, 3 artifact tests, 7 Batch 104 durable-execution lease tests, and 16 focused tests for Batches 294–297. The Batch 104 heartbeat-renewal test passed in this run.

## Syntax and configuration

- JavaScript/MJS/CJS syntax checks: **389 files checked; all passed**.
- `package.json` JSON parse: passed.
- Relative import resolution and application API references: covered by the passing Batch 102 regression tests.

## Archive validation

The complete cumulative source tree is packaged in the Batch 297 ZIP. The archive contains **930 files** and **949 ZIP entries**. `zip -T` and `unzip -t` passed. After extraction, all 930 files were present with no missing or extra files, and SHA-256 comparison found **0 file-content mismatches**. The selected regression suite was rerun after extraction and passed **39/39**.

## Limitations

- The full cumulative `npm test` suite was not run to completion in this validation run; only the selected regression suite listed above is claimed as passing.
- A positive end-to-end scenario that first establishes a fully current Batch 296 external attestation and then exercises successful Batch 297 renewal and terminal revocation was not executed.
- Live HTTP listener startup was not exercised. Express remains declared in `package.json`; runtime startup should be verified in an environment with project dependencies installed.

No GitHub commit was made.
