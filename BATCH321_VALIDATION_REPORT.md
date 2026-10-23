# Batch 321 Validation Report

## Regression tests

All selected test files below completed with TAP summaries and no failures:

| Test file / coverage | Tests | Passed |
|---|---:|---:|
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
| Batch 102 application/dependency checks | 13 | 13 |
| Artifact persistence | 3 | 3 |
| Batch 104 durable execution lease | 7 | 7 |
| **Total selected regression tests** | **82** | **82** |

Batch 321 coverage includes empty-history read-only behavior, invalid-action/reason/TTL rejection, refusal to mutate without a verified-current Batch 320 source, service/checkpoint/convergence/route wiring, lifecycle/receipt schema validation, and source receipt/checkpoint anchoring.

One combined shell run timed out while reaching the Batch 314 test file. The Batch 314 file was then rerun by itself and passed 4/4. Remaining listed test files were run separately and passed. This is not a claim that the full cumulative test suite passed.

## Syntax and configuration

- JavaScript/MJS/CJS syntax: **413/413 pass**.
- JSON parsing: **1/1 pass**.
- Relative import resolution and application API references are covered by Batch 102 regression tests.
- Application API and relative import checks are included in Batch 102 regression tests.

## Archive integrity

The cumulative source tree contains **1,074 files**. The final ZIP is checked with `zip -T` and `unzip -t`, extracted into a clean directory, and compared file-by-file against the packaged source using SHA-256. Archive-entry count and SHA-256 are reported alongside the delivered artifact.

## Not claimed as passing

- Full cumulative `npm test` with final TAP summary.
- Live HTTP listener startup with all runtime dependencies provisioned.
- Crash-injection at every lifecycle phase boundary.
- Fully provisioned positive end-to-end Batch 320 attestation → Batch 321 renewal/revocation → receipt → checkpoint advancement.
