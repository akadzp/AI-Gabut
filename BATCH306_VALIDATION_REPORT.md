# Agentic AI V4 — Batch 306 Validation Report

## Scope
Batch 306 adds signed external attestations for Batch 305 lifecycle finalization receipts, cross-generation receipt-prefix continuity, predecessor-attestation chaining, signing-key lifecycle binding, independent checkpoint-aware reconciliation, HTTP routes, and overall recovery-gate convergence.

## Focused regression validation
The following focused suites were run against the final source tree:

- Batch 102 application entrypoint, authentication, imports, API references, dependency declaration, and related checks.
- Artifact persistence tests.
- Batch 104 durable execution lease tests.
- Batch 299–306 lifecycle and external-attestation regression suites.

The combined focused run completed with **59 tests passed, 0 failed**. Batch 306's own suite completed with **4 tests passed, 0 failed**, including empty-history behavior, no fabricated source receipts, service/checkpoint/convergence/route wiring, and ledger schema binding checks.

## Syntax and source checks
- JavaScript/MJS/CJS syntax checks: **392/392 passed**.
- `package.json` JSON parsing: passed.
- Relative import resolution and application API references: passed through the Batch 102 regression suite.
- Batch 306 event allow-list, event schema validation, and independent checkpoint inventory references: passed focused wiring/schema tests.

## Archive validation
The final ZIP was tested with `zip -T` and `unzip -t`. It was then extracted to a separate directory. Source file counts and SHA-256 digests were compared between the packaged source tree and extracted tree. The focused regression suite and syntax checks were rerun against the extracted copy.

## Not claimed as complete
- The full cumulative `npm test` suite has not been run to a final TAP summary in this stage.
- A positive end-to-end run using a fully provisioned, current Batch 305 lifecycle receipt chain has not been completed.
- Live HTTP listener startup with runtime dependencies installed has not been tested.

## Repository actions
No GitHub commit was made. This archive is intended for local application and review.
