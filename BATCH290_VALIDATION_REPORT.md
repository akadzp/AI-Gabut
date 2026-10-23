# Batch 290 Validation Report

## Scope
Validation was performed on the cumulative source extracted from the supplied Batch 289 archive, with Batch 290 changes applied locally. No GitHub commit was made.

## Focused regression suite
Command:

```sh
node --test tests/apps/agentic-entrypoint-dependencies-batch102.mjs tests/apps/agentic-artifacts.mjs tests/apps/agentic-durable-execution-lease-batch104.mjs tests/apps/agentic-recovery-slo-v4-batch288-external-attestation.mjs tests/apps/agentic-recovery-slo-v4-batch289-external-attestation-lifecycle.mjs tests/apps/agentic-recovery-slo-v4-batch290-external-attestation.mjs
```

Result: **34 tests passed, 0 failed**.

Breakdown:
- Batch 102 entrypoint/dependency/API checks: 13/13 passed.
- Artifact tests: 3/3 passed.
- Batch 104 durable execution lease: 7/7 passed.
- Batch 288 external attestation regression: 3/3 passed.
- Batch 289 lifecycle regression: 5/5 passed.
- Batch 290 external attestation regression: 3/3 passed.

Batch 290-specific checks cover empty-history read-only behavior, service/API/checkpoint/convergence wiring, and malformed external-attestation binding schema validation.

## Syntax and configuration
- `node --check` over JavaScript, MJS, and CJS files: **382/382 passed**.
- `package.json` JSON parse: passed.
- Relative import resolution and server API reference checks: passed in Batch 102 tests.

## Full-suite attempt
`npm test` was attempted but reached the execution timeout after reporting subtest 1129. The captured output contained no failed subtests before timeout, but no final TAP summary was produced. Therefore the full cumulative suite is **not claimed as passing**.

## Runtime limitation
The `express` package is declared in `package.json` but is not installed in this validation environment. The HTTP listener was not started directly; route wiring and referenced application APIs were checked by regression tests.

## Archive validation
Final ZIP validation is performed after packaging: ZIP test, extraction test, source-file count, and SHA-256 equality between packaged files and extracted files. Final values are recorded in the delivery response.
