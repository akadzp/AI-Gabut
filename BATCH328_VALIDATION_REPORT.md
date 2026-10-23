# Agentic AI V4 — Batch 328 Validation Report

## Scope

This report covers the cumulative Batch 327 source plus Batch 328 signed external attestations for Batch 327 lifecycle finalization receipts, including receipt/finalization binding, receipt-prefix continuity, predecessor attestation continuity, signing-key lifecycle checks, independent checkpoint recovery, application convergence, and owner-scoped HTTP routes.

## Selected regression suites

The selected suites completed successfully across two test commands:

| Suite | Result |
|---|---:|
| Batch 102 — application, authentication, import, API, and dependency checks | 13/13 PASS |
| Artifact persistence | 3/3 PASS |
| Batch 104 — durable execution lease | 7/7 PASS |
| Batch 317 — lifecycle | 6/6 PASS |
| Batch 318 — external attestation | 4/4 PASS |
| Batch 319 — lifecycle | 6/6 PASS |
| Batch 320 — external attestation | 4/4 PASS |
| Batch 321 — lifecycle | 6/6 PASS |
| Batch 322 — external attestation | 6/6 PASS |
| Batch 323 — lifecycle | 6/6 PASS |
| Batch 324 — external attestation | 6/6 PASS |
| Batch 325 — lifecycle | 6/6 PASS |
| Batch 326 — external attestation | 6/6 PASS |
| Batch 327 — lifecycle | 6/6 PASS |
| Batch 328 — external attestation | 6/6 PASS |
| **Total selected regression tests** | **91/91 PASS** |

The Batch 322, Batch 324, and Batch 326 regression tests had their exact cumulative event-inventory assertions updated to include Batch 328. All affected suites passed after that change.

Batch 328 tests cover empty-history safety, no fabricated Batch 327 source receipts, service binding requirements, independent checkpoint event inventory, overall convergence and owner-scoped route wiring, and strict event schema/predecessor fields.

## Syntax and configuration

- JavaScript/MJS/CJS syntax checks with `node --check`: **420/420 PASS**.
- JSON parsing: **1/1 PASS**.
- Relative import resolution and top-level HTTP application API references: **PASS** through Batch 102 regression tests.

## ZIP and extraction validation

The final ZIP is checked with `zip -T` and `unzip -t`, then extracted to a separate directory. Packaged and extracted source-file inventories are compared by SHA-256; no missing, extra, or mismatched source files are accepted. The extracted tree passed syntax checks (**420/420**) and JSON parsing (**1/1**). Focused post-extraction regression suites for Batch 322, 324, 326, 327, and 328 plus Batch 102, artifact persistence, and Batch 104 passed **53/53**.

An attempted single combined post-extraction run of all 91 selected tests timed out during the Batch 325 suite after earlier tests had passed; no assertion failure was reported before the timeout. The complete 91-test selection had passed on the working tree in two completed commands. Therefore, this report does not claim all 91 were rerun successfully in one post-extraction invocation. Final file counts, archive size, and archive SHA-256 are recorded in the delivery summary.

## Not claimed as verified

- Full cumulative `npm test` with a complete final TAP summary.
- Fully provisioned positive end-to-end flow from verified-current Batch 327 lifecycle receipts through Batch 328 attestation and checkpoint advancement.
- Live HTTP listener startup with all runtime dependencies installed.
- Exhaustive crash-injection at every attestation/checkpoint phase boundary.

PASS claims are limited to the selected regression suites, syntax/configuration checks, and archive-integrity checks described here.

## Source-control policy

No GitHub commit was performed.
