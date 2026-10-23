# Batch 303 Validation Report

## Focused regression suite

Command:

```sh
node --test \
  tests/apps/agentic-entrypoint-dependencies-batch102.mjs \
  tests/apps/agentic-artifacts.mjs \
  tests/apps/agentic-durable-execution-lease-batch104.mjs \
  tests/apps/agentic-recovery-slo-v4-batch299-external-attestation-lifecycle.mjs \
  tests/apps/agentic-recovery-slo-v4-batch300-external-attestation.mjs \
  tests/apps/agentic-recovery-slo-v4-batch301-external-attestation-lifecycle.mjs \
  tests/apps/agentic-recovery-slo-v4-batch302-external-attestation.mjs \
  tests/apps/agentic-recovery-slo-v4-batch303-external-attestation-lifecycle.mjs
```

**Result: 46 tests passed, 0 failed.** Batch 303 contributes five tests covering empty-history behavior, invalid actions/challenge parameters, source-current gating, service/checkpoint/convergence/route wiring, and event-schema binding requirements. Batch 104 heartbeat renewal and durable lease regression tests passed in this run.

## Syntax and configuration
- JavaScript/MJS/CJS files checked with `node --check`: **395 passed**.
- `package.json` parsed successfully: **1 passed**.
- Relative imports and top-level application APIs are covered by Batch 102 tests and passed.

## Archive validation
- Source/project files: **965** before and after extraction.
- ZIP entries: **984**.
- `zip -T`: **PASS**.
- `unzip -t`: **PASS**; no compressed-data errors.
- SHA-256 comparison of every source/project file before and after extraction: **0 differences**.
- Focused regression suite rerun against the extracted final archive: **46 passed, 0 failed**.
- Syntax checks rerun against the extracted final archive: **395 passed**.
- `package.json` parse after extraction: **PASS**.

## Remaining unverified integration
- Full cumulative `npm test` to a final TAP summary.
- Positive end-to-end renewal/revocation using a fully provisioned, current Batch 302 attestation chain.
- Live HTTP listener startup with runtime dependencies installed.

No GitHub commit was made.
