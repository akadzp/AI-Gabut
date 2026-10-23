# Batch 325 Validation Report

## Scope

Batch 325 adds a renewal/revocation lifecycle for Batch 324 external attestations, including append-only intent/action/finalization/receipt events, cross-generation predecessor and replacement binding, terminal revocation, signing-key lifecycle checks, recovery reconciliation, checkpoint advancement, global recovery-gate convergence, and owner-scoped HTTP routes.

## Regression tests

**63/63 selected regression tests passed** in the pre-packaging combined Node TAP run (`1..63`, `# pass 63`, `# fail 0`). The selection included:

- Batch 102 application, authentication, dependency, import-resolution, and API-reference checks: 13/13.
- Artifact persistence: 3/3.
- Batch 104 durable execution lease: 7/7.
- Batch 319 lifecycle: 6/6.
- Batch 320 external attestation: 4/4.
- Batch 321 lifecycle: 6/6.
- Batch 322 external attestation: 6/6.
- Batch 323 lifecycle: 6/6.
- Batch 324 external attestation: 6/6.
- Batch 325 lifecycle: 6/6.

The Batch 322 and Batch 324 static schema assertions were updated to accept the cumulative Batch 325 event-type allowlist. The updated regression selection passed. After extraction, the 56 non-lease tests passed together (`56/56`), and Batch 104 passed separately (`7/7`). A combined post-extraction run showed one transient Batch 104 lease-heartbeat timing failure under concurrent test load; the same Batch 104 suite passed on isolated rerun. No Batch 325 or Batch 319–324 test failed.

## Syntax and configuration

- JavaScript/MJS/CJS syntax checks: **417/417 passed**.
- JSON parsing: **1/1 passed**.
- Relative-import resolution and top-level application API reference checks passed through Batch 102 regression tests.

## Archive validation

The final ZIP was tested with both `zip -T` and `unzip -t`. The archive was then extracted to a separate directory and source-file SHA-256 hashes were compared against the packaged source tree. The extracted tree had 1,097 files, with zero missing files, zero extra files, and zero SHA-256 mismatches. Exact archive size and digest are provided in the release summary accompanying this ZIP.

## Not claimed as verified

- Full cumulative `npm test` was not run to a final TAP summary.
- A fully provisioned positive end-to-end flow from verified-current Batch 324 attestation through Batch 325 renewal/revocation, finalization receipt, and checkpoint advancement was not executed.
- Crash injection at every lifecycle/checkpoint phase boundary was not executed.
- The live HTTP listener was not started with runtime dependencies installed; HTTP route registration and application API references were checked statically.
- `verify:recovery-slo-export` was not run because the script requires a `--bundle` input.

## Source-control policy

No GitHub commit was performed.
