# Batch 322 Validation Report

## Regression tests

The selected regression files were run individually against the final source tree. Batch 104 was rerun with Node's test-runner force-exit option because child-process handles kept the initial runner alive after all TAP cases had passed. All listed TAP summaries completed with no test failures.

| Test file / coverage | Tests | Passed |
|---|---:|---:|
| Batch 322 external attestation | 6 | 6 |
| Batch 321 lifecycle | 6 | 6 |
| Batch 320 external attestation | 4 | 4 |
| Batch 319 lifecycle | 6 | 6 |
| Batch 318 external attestation | 4 | 4 |
| Batch 317 lifecycle | 6 | 6 |
| Batch 316 external attestation | 4 | 4 |
| Batch 315 lifecycle | 6 | 6 |
| Batch 314 external attestation | 4 | 4 |
| Batch 313 lifecycle | 6 | 6 |
| Batch 312 external attestation | 4 | 4 |
| Batch 311 lifecycle | 5 | 5 |
| Batch 310 external attestation | 4 | 4 |
| Batch 309 lifecycle | 5 | 5 |
| Batch 102 application/dependency checks | 13 | 13 |
| Artifact persistence | 3 | 3 |
| Batch 104 durable execution lease | 7 | 7 |
| **Total selected regression tests** | **93** | **93** |

Batch 322 coverage includes empty-history read-only behavior, no fabricated Batch 321 source receipts, source receipt/finalization binding, receipt-chain and predecessor fields, checkpoint snapshot inventory, application convergence and owner-scoped routes, and event schema validation.

The selected tests do not constitute a full cumulative `npm test` run.

## Syntax and configuration

- JavaScript/MJS/CJS syntax: **414/414 pass** (including the new Batch 322 test file).
- `package.json` JSON parsing: **1/1 pass**.
- Relative imports and application API wiring are covered by the Batch 102 regression test.

## Archive integrity

The cumulative source tree is packaged into a ZIP, validated with `zip -T` and `unzip -t`, extracted into a clean directory, and compared file-by-file against the packaged source using SHA-256. Final file/entry counts and archive SHA-256 are reported with the delivered artifact.

## Not claimed as passing

- Full cumulative `npm test` with a complete TAP summary.
- Live HTTP listener startup with all runtime dependencies provisioned.
- Crash-injection at every lifecycle/checkpoint phase boundary.
- Fully provisioned positive end-to-end Batch 321 lifecycle receipt → Batch 322 external attestation → checkpoint advancement.
