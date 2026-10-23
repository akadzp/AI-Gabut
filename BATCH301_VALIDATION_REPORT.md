# Agentic AI V4 — Batch 301 Validation Report

## Scope
Validated the cumulative Batch 300 source after adding Batch 301 renewal/revocation lifecycle for Batch 300 external attestations, finalization receipts, application integration, owner-scoped HTTP routes, and focused regression tests. No GitHub commit was made.

## Focused regression tests
Command:

```sh
node --test \
  tests/apps/agentic-entrypoint-dependencies-batch102.mjs \
  tests/apps/agentic-artifacts.mjs \
  tests/apps/agentic-durable-execution-lease-batch104.mjs \
  tests/apps/agentic-recovery-slo-v4-batch297-external-attestation-lifecycle.mjs \
  tests/apps/agentic-recovery-slo-v4-batch298-external-attestation.mjs \
  tests/apps/agentic-recovery-slo-v4-batch299-external-attestation-lifecycle.mjs \
  tests/apps/agentic-recovery-slo-v4-batch300-external-attestation.mjs \
  tests/apps/agentic-recovery-slo-v4-batch301-external-attestation-lifecycle.mjs
```

Result: **46/46 tests passed**. Batch 301-specific tests: **5/5 passed**, covering empty-history read-only behavior, invalid action/challenge parameter rejection, the current-source gate, service/checkpoint/convergence/route wiring, and lifecycle/receipt schema bindings. The selected regression set also includes Batch 102 application/API/dependency checks, artifact tests, Batch 104 durable execution lease tests, and Batches 297–300. Batch 104 heartbeat renewal passed in this run.

## Syntax and configuration
- JavaScript/MJS/CJS files checked with `node --check`: **393/393 passed**.
- JSON configuration parse: **1/1 passed**.
- Relative-import and application API reference checks: passed through Batch 102 regression tests.
- Live HTTP listener startup: not exercised; Express is declared in `package.json` but is not installed in this validation environment.

## Archive validation
The final cumulative source ZIP was tested with `zip -T` and `unzip -t`, extracted into a separate directory, and checked for file inventory equality and SHA-256 equality for every source/project file. Final archive metrics and digest are provided with the delivery.

## Known validation limits
- Full cumulative `npm test` was not run to a final TAP summary; no full-suite pass is claimed.
- Positive end-to-end lifecycle mutation with a fully provisioned current Batch 300 external-attestation chain, including a real renewal/revocation, finalization receipt, and checkpoint advancement, was not exercised.
- Live HTTP listener startup was not exercised.

No GitHub commit was made.
