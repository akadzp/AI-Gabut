# Agentic AI V4 — Batch 307 Validation Report

## Scope
Batch 307 adds renewal/revocation lifecycle operations for Batch 306 external attestations, cross-generation supersession, lifecycle finalization receipts, signing-key lifecycle binding, independent checkpoint-aware recovery, owner-scoped HTTP routes, and overall recovery-gate convergence.

## Focused regression validation
The following selected suites were run against the working source tree:
- Batch 102 application entrypoint, authentication, import resolution, application API references, and dependency checks.
- Artifact persistence tests.
- Batch 104 durable execution lease tests.
- Batch 299–307 lifecycle and external-attestation regression suites.

**Result: 64 tests passed, 0 failed.** Batch 307's own suite completed with 5 tests passed, 0 failed. Tests cover empty-history behavior, invalid action/reason/TTL rejection, current-source gating, service/checkpoint/convergence/route wiring, and ledger schema bindings.

## Syntax and configuration
- JavaScript/MJS/CJS syntax checks: **399/399 passed**.
- JSON parsing: **1/1 passed**.
- Relative import resolution and server-to-application API references passed through Batch 102 regression tests.

## Archive validation
The final ZIP is tested with `zip -T` and `unzip -t`, extracted into a separate directory, and compared file-by-file using SHA-256. Focused regression tests and syntax checks are then rerun against the extracted source.

## Not claimed as complete
- Full cumulative `npm test` was not run to a final TAP summary in this stage.
- A positive end-to-end renewal/revocation run using a fully provisioned current Batch 306 attestation chain was not completed.
- Live HTTP listener startup with runtime dependencies installed was not tested.

## Repository actions
No GitHub commit was made. This ZIP is intended for local application and review.
