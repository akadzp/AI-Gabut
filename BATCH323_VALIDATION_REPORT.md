# Batch 323 Validation Report

## Regression tests

The following selected regression test files were run individually or in small sequential groups against the modified source tree. Each reported TAP summary completed with no test failures.

| Test coverage | Tests | Passed |
|---|---:|---:|
| Batch 323 lifecycle | 6 | 6 |
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
| **Total selected regression tests** | **99** | **99** |

Batch 323 coverage includes empty-history read-only behavior, invalid action/reason/TTL rejection, the Batch 322 `verified_current` source gate, service and checkpoint inventory, overall convergence and owner-scoped route wiring, lifecycle event schema checks, and source receipt/checkpoint binding checks. The Batch 322 schema test was updated because the cumulative event allowlist now includes Batch 323 event types.

An earlier broad multi-file test invocation timed out after reporting passing cases through Batch 313; it did not provide a complete summary and is not counted as a full-suite pass. The affected later test groups were then run separately and passed. The full cumulative `npm test` is not claimed as passing.

## Syntax and configuration

- JavaScript/MJS/CJS syntax: **415/415 pass**.
- JSON parsing: **1/1 pass** (`package.json`).
- Relative imports and application API references: covered by the passing Batch 102 regression checks.

## Archive integrity

The final cumulative source tree is packaged as a ZIP, checked with `zip -T` and `unzip -t`, extracted into a clean directory, then compared file-by-file using SHA-256. Exact final file/entry counts and ZIP SHA-256 are recorded in the delivery summary.

## Not claimed as passing

- Full cumulative `npm test` with a complete TAP summary.
- Live HTTP listener startup with all runtime dependencies provisioned.
- Crash-injection at every lifecycle/receipt/checkpoint phase boundary.
- Fully provisioned positive end-to-end Batch 322 external attestation → Batch 323 renewal/revocation → finalization receipt → checkpoint advancement.
