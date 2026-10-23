# Batch 296 Validation Report

## Scope
- Added Batch 296 external attestation for Batch 295 lifecycle finalization receipts.
- Added event-schema validation and cumulative ledger/checkpoint inventory support.
- Added application wrappers, recovery-gate convergence, and four owner-scoped HTTP routes.
- Added three focused Batch 296 regression tests.

## Regression tests
- Batch 293–296 focused tests, Batch 102 entrypoint/dependency checks, and artifact tests: **32/32 passed**.
- Batch 296 focused tests: **3/3 passed** (included in the 32-test run).
- Batch 104 durable execution lease tests: **7/7 passed** in an isolated run. A combined run once produced a transient heartbeat timeout (`WORK_EXECUTION_LEASE_LOST`); the isolated rerun passed all seven cases.
- Full cumulative `npm test` was not run to completion in this batch; no full-suite pass is claimed.

## Syntax and archive
- JavaScript/MJS/CJS syntax checks: **388/388 passed** before packaging.
- `package.json` JSON parse: passed.
- The final archive contains **924 files** and **943 ZIP entries** (including directory entries).
- ZIP integrity was checked with `zip -T` and `unzip -t`.
- The extracted source tree was compared against the packaged source by SHA-256; no file differences were found.
- Syntax and focused regression tests were rerun from the extracted archive.

No GitHub commit was performed.
