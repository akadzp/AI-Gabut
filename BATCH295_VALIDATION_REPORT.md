# Batch 295 Validation Report

## Source archive

- Cumulative base: Batch 294 complete source ZIP.
- Stage added: Batch 295 external-attestation renewal/revocation lifecycle.
- GitHub commit: none.

## Focused regression tests

Command covered:

- `tests/apps/agentic-entrypoint-dependencies-batch102.mjs`
- `tests/apps/agentic-artifacts.mjs`
- `tests/apps/agentic-durable-execution-lease-batch104.mjs`
- Batch 290 external-attestation tests
- Batch 291 lifecycle tests
- Batch 292 external-attestation tests
- Batch 293 lifecycle tests
- Batch 294 external-attestation tests
- Batch 295 lifecycle tests

Result: **47 tests passed, 0 failed**.

Batch 104 lease regression subset: **7/7 PASS**, including heartbeat renewal, cross-process exclusion, fencing, atomic storage, and abandoned-lock recovery.

## Cumulative test suite

`npm test` was attempted with a 300-second execution limit. It emitted output through subtest 1129 and then timed out. No final TAP summary was available. The full cumulative suite is not claimed as passing, and no conclusion is drawn about tests that were not reached.

## Syntax and configuration

- JavaScript/MJS/CJS files checked with `node --check`: **387/387 PASS**.
- JSON files parsed: **1/1 PASS**.
- Relative import resolution and application API references are covered by Batch 102 tests: PASS.

## Archive validation

The final ZIP was tested with `zip -T` and `unzip -t`. The archive was extracted to a clean directory and all extracted files were compared against the packaged source using SHA-256. The final handoff reports the archive file count, entry count, size, and SHA-256 digest.

## Remaining validation gaps

- Positive end-to-end lifecycle execution from a verified-current Batch 294 attestation through renewal/revocation, finalization receipt, and checkpoint advancement is not yet demonstrated.
- Live HTTP listener startup was not tested.
