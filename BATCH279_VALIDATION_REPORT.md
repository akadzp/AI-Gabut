# Batch 279 Validation Report

## Focused regression suites
The following suites passed when run individually against the Batch 279 source tree:

- Batch 102 application entrypoint, dependency, import, and API checks: 13/13.
- Artifact tests: 3/3.
- Batch 104 durable execution lease: 7/7. One combined-run attempt transiently failed the heartbeat test with `WORK_EXECUTION_LEASE_LOST`; the heartbeat-only rerun and the full Batch 104 suite then passed.
- Batch 276 external-attestation regressions: 3/3.
- Batch 277 lifecycle regressions: 3/3.
- Batch 278 external-attestation regressions: 3/3.
- Batch 279 lifecycle regressions: 3/3.

Total selected regression tests passed across the final isolated runs: 35/35.

## Syntax and structure
- JavaScript/MJS syntax parsing with Node VM modules: 371/371 files passed.
- Direct `node --check` passed for the modified core, application, server, and Batch 279 test files.
- Batch 102 import-resolution and application API reference checks passed.
- Batch 102 confirmed the Express dependency is declared in `package.json`.

## Archive checks
The release ZIP is tested with `zip -T` and `unzip -t`. The archive is extracted into a fresh directory, then file inventories and SHA-256 hashes are compared against the source tree. Regression tests are rerun from the extracted tree.

## Limitations
- The full cumulative `npm test` suite was not run to completion; no full-suite PASS is claimed.
- A positive end-to-end flow that creates a current Batch 278 external attestation, renews/revokes it through Batch 279, finalizes the lifecycle receipt, advances the independent checkpoint, and verifies the complete chain was not exercised.
- The HTTP listener was not started as an independent runtime smoke test; route wiring and application API references were checked.
