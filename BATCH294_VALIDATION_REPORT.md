# Batch 294 Validation Report

## Regression tests

Focused test command:

```bash
node --test \
  tests/apps/agentic-recovery-slo-v4-batch294-external-attestation.mjs \
  tests/apps/agentic-recovery-slo-v4-batch293-external-attestation-lifecycle.mjs \
  tests/apps/agentic-recovery-slo-v4-batch292-external-attestation.mjs \
  tests/apps/agentic-recovery-slo-v4-batch291-external-attestation-lifecycle.mjs \
  tests/apps/agentic-entrypoint-dependencies-batch102.mjs \
  tests/apps/agentic-artifacts.mjs
```

Result: **32 tests passed, 0 failed**.

Separate durable execution lease test:

```bash
node --test tests/apps/agentic-durable-execution-lease-batch104.mjs
```

Result: **7 tests passed, 0 failed**. The lease-heartbeat test passed in this run.

## Syntax and configuration

- JavaScript/MJS/CJS files checked with `node --check`: **386/386 passed**.
- JSON files parsed: **1/1 passed**.
- Relative import resolution and application API references: covered by Batch 102 regression tests and passed.

## Archive integrity

The final ZIP was tested with `zip -T` and `unzip -t`. It contains **911 files** and **930 ZIP entries**. It was extracted to a clean directory; the extracted inventory contained 911 files, with **0 missing files, 0 extra files, and 0 SHA-256 mismatches**. The final archive SHA-256 is recorded in the delivery summary (outside this report to avoid a self-referential archive hash).

## Limitations

- Full cumulative `npm test` was not run to a final TAP summary and is not claimed as passing.
- Positive end-to-end issuance against a fully verified-current Batch 293 receipt chain with independent checkpoint enabled has not been completed.
- Live HTTP listener startup was not exercised in this validation run.
- No GitHub commit was made.
