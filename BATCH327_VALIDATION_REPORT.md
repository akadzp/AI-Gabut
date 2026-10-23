# Agentic AI V4 — Batch 327 Validation Report

## Scope

This report covers the cumulative Batch 326 source plus Batch 327 renewal/revocation lifecycle support for Batch 326 external attestations, finalization receipts, checkpoint recovery, application convergence, and owner-scoped HTTP routes.

## Selected regression suites

All suites were run individually and passed:

| Suite | Result |
|---|---:|
| Batch 102 — application/dependency checks | 13/13 PASS |
| Artifact persistence | 3/3 PASS |
| Batch 104 — durable execution lease | 7/7 PASS |
| Batch 319 — lifecycle | 6/6 PASS |
| Batch 320 — external attestation | 4/4 PASS |
| Batch 321 — lifecycle | 6/6 PASS |
| Batch 322 — external attestation | 6/6 PASS |
| Batch 323 — lifecycle | 6/6 PASS |
| Batch 324 — external attestation | 6/6 PASS |
| Batch 325 — lifecycle | 6/6 PASS |
| Batch 326 — external attestation | 6/6 PASS |
| Batch 327 — lifecycle | 6/6 PASS |
| **Total selected regression tests** | **75/75 PASS** |

Three existing regression tests (Batch 322, Batch 324, Batch 326) had their exact cumulative event-allowlist assertions updated to include the new Batch 327 event types. Their suites pass after the update.

## Syntax and configuration

- JavaScript/MJS/CJS files checked with `node --check`: **419/419 PASS**.
- JSON files parsed: **1/1 PASS**.
- Relative import resolution and application API references: covered by Batch 102 tests, **PASS**.

## ZIP and extraction

The final ZIP was checked with `zip -T` and `unzip -t`, then extracted to a separate directory. Source-file inventories and SHA-256 digests were compared before and after extraction. The final counts and digest are recorded in the delivery summary.

After extraction, Batch 325, Batch 326, and Batch 327 regression suites were rerun individually: **18/18 PASS**. Syntax was also rechecked across all 419 JavaScript/MJS/CJS files: **419/419 PASS**; JSON parsing was **1/1 PASS**.

## Not claimed as passing

- Full cumulative `npm test` with a complete final TAP summary.
- Fully provisioned positive end-to-end flow through Batch 326 current attestation → Batch 327 renewal/revocation → finalization receipt → checkpoint advancement.
- Live HTTP listener startup with runtime dependencies.
- Crash-injection at every lifecycle and checkpoint boundary.

The PASS claims above are limited to the selected regression suites, syntax/configuration checks, and archive-integrity checks.
