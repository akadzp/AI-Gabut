# Batch 317 Validation Report

## Scope

This report covers the cumulative Agentic AI V4 source tree through Batch 317: renewal/revocation lifecycle for Batch 316 external attestations, signed lifecycle events, supersession, finalization receipts, cross-generation receipt continuity, signing-key lifecycle checks, checkpoint-aware reconciliation, owner-scoped APIs/routes, and recovery-gate convergence.

## Focused regression tests

The following selected suites completed individually with TAP summaries and no failures:

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
| **Total selected regression tests** | **62/62 PASS** |

The Batch 317 suite verifies empty-history read-only behavior, invalid action/reason/TTL rejection before mutation, the verified-current source gate, service and checkpoint-inventory wiring, owner-scoped routes, lifecycle/receipt schema fields, and Batch 316 source-receipt/checkpoint binding.

A loop that attempted to invoke all selected suites sequentially timed out at its final Batch 317 invocation without emitting a TAP summary. Batch 317 was rerun independently and passed 6/6. All other suites had individual TAP summaries and passed.

## Syntax and configuration

- JavaScript/MJS/CJS files checked with `node --check`: **409/409 PASS**.
- JSON files parsed: **1/1 PASS**.
- Relative import and application API reference checks: covered by the Batch 102 regression suite and passed.

## Archive and extraction

The final ZIP passed `zip -T` and `unzip -t`. It contains **1,050 source/project files** and **1,069 ZIP entries**. After clean extraction, the tree contained 1,050 files with **0 missing files, 0 extra files, and 0 SHA-256 differences**. The selected Batch 317 suite passed **6/6** against the extracted tree, and extracted-tree syntax checks passed **409/409** with JSON parsing **1/1 PASS**.

## Limitations

- The full cumulative `npm test` suite was not run to a final TAP summary; the results above are selected regression suites only.
- A positive end-to-end test provisioning a fully current Batch 316 attestation chain, executing Batch 317 renewal/revocation, finalizing a receipt, and advancing a real independent checkpoint was not completed.
- Crash injection at every lifecycle phase boundary was not completed.
- Live HTTP listener startup and end-to-end HTTP requests were not tested.

No GitHub commit was made.
