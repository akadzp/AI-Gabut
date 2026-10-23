# Agentic AI V4 — Batch 329 Validation Report

## Scope

Validation was performed on the complete cumulative Batch 328 source with Batch 329 added. The final archive is intended for local application; no GitHub commit was made.

## Selected regression tests

The following focused suites were run individually against the extracted source. All passed:

| Suite | Result |
|---|---:|
| Batch 102 — application entrypoint/dependency checks | 13/13 PASS |
| Artifact persistence | 3/3 PASS |
| Batch 104 — durable execution lease | 7/7 PASS |
| Batch 322 — external attestation | 6/6 PASS |
| Batch 324 — external attestation | 6/6 PASS |
| Batch 326 — external attestation | 6/6 PASS |
| Batch 327 — lifecycle | 6/6 PASS |
| Batch 328 — external attestation | 6/6 PASS |
| Batch 329 — lifecycle | 6/6 PASS |
| **Total selected tests** | **59/59 PASS** |

Batch 329 tests cover empty-history behavior, invalid action/reason/TTL rejection, refusal to mutate without a `verified_current` Batch 328 source, service and owner-scoped route wiring, lifecycle/receipt schema checks, and source receipt/checkpoint binding references.

A combined sequential test harness timed out while entering the Batch 328 suite after earlier suites passed. The Batch 328 and Batch 329 suites were rerun separately against the extracted source and each passed 6/6. No assertion failure was reported by the timed-out combined harness.

## Syntax and configuration

| Check | Result |
|---|---:|
| JavaScript/MJS/CJS files checked with `node --check` | 421/421 PASS |
| JSON files parsed | 1/1 PASS |
| Relative import and application API references | Covered by Batch 102 regression suite, 13/13 PASS |

## Archive and extraction

The cumulative ZIP was tested with both `zip -T` and `unzip -t`. The ZIP was extracted to a separate directory and every file was compared by relative path and SHA-256.

| Check | Result |
|---|---:|
| Source/project files in final package | 1,118 |
| ZIP entries including directories | 1,137 |
| Missing files after extraction | 0 |
| Extra files after extraction | 0 |
| SHA-256 file mismatches | 0 |
| Archive integrity | PASS |

## Not claimed as verified

- Full cumulative `npm test` has not been run to a final TAP summary.
- A fully provisioned positive end-to-end flow from a current Batch 328 external attestation through Batch 329 renewal/revocation, finalization receipt, and checkpoint advancement has not been completed.
- Live HTTP listener startup with all runtime dependencies has not been tested.
- Exhaustive crash-injection at every lifecycle and checkpoint boundary has not been performed.

The PASS results above apply to the selected regression tests, syntax/configuration checks, and archive integrity checks only; they do not establish full-system verification.
