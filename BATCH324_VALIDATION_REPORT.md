# Batch 324 Validation Report

## Focused regression tests

The following test files were run individually. Each completed with a TAP summary and zero failures:

| Test file / coverage | Tests | Passed |
|---|---:|---:|
| Batch 324 external attestation | 6 | 6 |
| Batch 323 lifecycle | 6 | 6 |
| Batch 322 external attestation | 6 | 6 |
| Batch 321 lifecycle | 6 | 6 |
| Batch 320 external attestation | 4 | 4 |
| Batch 319 lifecycle | 6 | 6 |
| Batch 318 external attestation | 4 | 4 |
| Batch 317 lifecycle | 6 | 6 |
| Batch 102 application/dependency checks | 13 | 13 |
| Artifact persistence | 3 | 3 |
| Batch 104 durable execution lease | 7 | 7 |
| **Total selected regression tests** | **67** | **67** |

Batch 324 tests cover empty-history behavior, non-fabrication when Batch 323 receipts do not exist, service wiring, independent checkpoint inventory, owner-scoped HTTP routes, overall convergence, schema validation, receipt/finalization binding, predecessor continuity, and signing-key lifecycle fields. After extraction, Batch 324, Batch 323, and Batch 322 suites were rerun for **18/18 passing tests**.

An earlier shell sequence running multiple files timed out while beginning Batch 319. Batch 319 and subsequent suites were then run separately and completed successfully. The interrupted combined invocation is not counted as a full-suite pass.

## Syntax and configuration

- JavaScript/MJS/CJS syntax: **416/416 passed** before packaging and **416/416 passed** after extraction.
- JSON parsing: **1/1 passed** (`package.json`) before packaging and after extraction.
- Application API, route wiring, and relative import coverage: included in focused regression tests.

## Archive integrity

The final ZIP was checked using `zip -T` and `unzip -t`, extracted into a clean directory, and compared file-by-file with SHA-256. The archive contains **1,090 source/project files**; extraction produced **1,090 files**, with **0 missing files, 0 extra files, and 0 SHA-256 differences**. The ZIP contains no duplicate file paths.

## Not claimed as passing

- Full cumulative `npm test` with one complete TAP summary.
- Live HTTP listener startup under production runtime configuration.
- Crash-injection at every lifecycle, receipt, and checkpoint boundary.
- Fully provisioned positive end-to-end Batch 323 finalization receipt → Batch 324 external attestation → checkpoint advancement.
