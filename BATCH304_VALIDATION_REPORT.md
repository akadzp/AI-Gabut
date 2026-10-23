# Batch 304 Validation Report

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
  tests/apps/agentic-recovery-slo-v4-batch303-external-attestation-lifecycle.mjs \
  tests/apps/agentic-recovery-slo-v4-batch304-external-attestation.mjs
```

**Result: 50 tests passed, 0 failed.** Batch 304 contributes four tests covering empty-history behavior, no-source-receipt behavior, service/checkpoint/convergence/route wiring, and event-schema binding requirements. Batch 104 durable execution lease regressions, including heartbeat renewal, passed in this run.

## Syntax and configuration
- JavaScript/MJS/CJS files checked with `node --check`: **396 passed**.
- `package.json` parsed successfully.
- Relative imports and top-level application API references are covered by Batch 102 regression tests and passed.

## Archive validation
- Source/project files: **971** before and after extraction.
- ZIP entries: **990** (971 files and 19 directory entries).
- `zip -T`: **PASS**.
- `unzip -t`: **PASS**, with no compressed-data errors.
- SHA-256 comparison of every source/project file before and after extraction: **0 differences**.
- Focused regression suite rerun against the extracted final archive: **50 passed, 0 failed**.
- Syntax checks rerun against the extracted final archive: **396 passed**.
- `package.json` parse after extraction: **PASS**.

## Remaining unverified integration
- Full cumulative `npm test` to a final TAP summary.
- Positive end-to-end attestation using a fully provisioned, current Batch 303 lifecycle finalization receipt chain.
- Live HTTP listener startup with runtime dependencies installed.

No GitHub commit was made.
