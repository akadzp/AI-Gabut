# Agentic AI V4 — Batch 308 Validation Report

## Scope
Batch 308 adds external attestation for Batch 307 lifecycle finalization receipts, cross-generation receipt continuity, signing-key lifecycle binding, independent checkpoint-aware recovery, owner-scoped HTTP routes, and overall recovery-gate convergence.

## Focused regression validation
The following selected suites were run against the working source and then rerun against the final extracted archive:
- Batch 102 entrypoint/dependency/authentication/import/API checks: 13 tests.
- Artifact persistence tests: 3 tests.
- Batch 104 durable execution lease tests: 7 tests.
- Batch 299–308 lifecycle and external-attestation suites: 45 tests.

**Result: 68 tests passed, 0 failed.** Batch 308's own suite completed with 4 tests passed, 0 failed. Coverage includes empty-history behavior, absent source receipt handling, service/checkpoint/convergence/route wiring, and ledger schema fields.

## Syntax and configuration
- JavaScript/MJS/CJS syntax checks: **400/400 passed**.
- `package.json` JSON parse: **1/1 passed**.
- Relative import resolution and server-to-application API references passed through Batch 102 regression tests.

## Archive validation
- Source/project files: **994**.
- ZIP entries including directory entries: **1,013**.
- `zip -T`: passed.
- `unzip -t`: passed.
- Extracted file count and paths: identical to the staged source.
- SHA-256 comparison for all source files before and after extraction: **994/994 identical**.
- Focused regression tests after extraction: **68/68 passed**.
- Syntax checks after extraction: **400/400 passed**.

## Not claimed as complete
- Full cumulative `npm test` has not been run to a final TAP summary.
- Positive end-to-end external attestation over a fully provisioned current Batch 307 lifecycle receipt chain remains unverified.
- Live HTTP listener startup with runtime dependencies installed remains unverified.

## Repository actions
No GitHub commit was made. This ZIP is intended for local application and review.
