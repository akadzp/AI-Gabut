# Batch 318 Final Validation Report

## Scope

This report covers the cumulative Agentic AI V4 source tree through Batch 318: external attestation for Batch 317 lifecycle finalization receipts, cross-generation receipt continuity, signing-key lifecycle verification, checkpoint-aware reconciliation, owner-scoped API wrappers/routes, and recovery-gate convergence.

## Focused regression tests

The following suites were executed as separate Node test processes. Each completed with a TAP summary and zero failures.

| Suite | Passed |
|---|---:|
| Batch 102 application/dependency/import/API checks | 13/13 |
| Artifact persistence | 3/3 |
| Batch 104 durable execution lease | 7/7 |
| Batch 310 external attestation | 4/4 |
| Batch 311 lifecycle | 5/5 |
| Batch 312 external attestation | 4/4 |
| Batch 313 lifecycle | 6/6 |
| Batch 314 external attestation | 4/4 |
| Batch 315 lifecycle | 6/6 |
| Batch 316 external attestation | 4/4 |
| Batch 317 lifecycle | 6/6 |
| Batch 318 external attestation | 4/4 |
| **Total selected regression tests** | **66/66 PASS** |

The Batch 318 suite verifies empty-history read-only behavior, no fabricated source receipts, service/API/convergence/checkpoint-inventory wiring, owner-scoped route declarations, and receipt/generation/signature/predecessor schema checks. Batch 317 and Batch 316 suites were rerun after implementation and passed. All suites in the table passed individually.

## Syntax and configuration

- JavaScript/MJS/CJS files checked with `node --check`: **410/410 PASS**.
- JSON files parsed: **1/1 PASS**.
- Relative import and application API checks: covered by Batch 102 tests and passed.

## Archive and extraction

The final ZIP was tested with `zip -T` and `unzip -t`, extracted to a clean directory, and compared file-by-file using SHA-256. Archive size, entry count, and SHA-256 are provided in the release handoff. Syntax and focused regression tests were repeated against the extracted source tree.

## Limitations

- The full cumulative `npm test` suite was not run to a final TAP summary; the results above are focused regression suites, not a claim that all V4 tests pass.
- A positive end-to-end test that provisions a fully current Batch 317 receipt chain, creates Batch 318 attestations, and advances a live independent checkpoint was not completed.
- Crash injection at every interruption boundary was not completed.
- Live HTTP listener startup and owner-scoped route requests with runtime dependencies were not tested end to end.
- A combined shell run of multiple regression suites timed out while entering the Batch 317 suite; Batch 317 was rerun separately and passed 6/6, and Batch 318 passed separately 4/4. No individual test failure remains in the selected suites.

No GitHub commit was made.
