# Batch 326 Validation Report

## Scope

Batch 326 adds signed external attestations for Batch 325 lifecycle finalization receipts. The implementation validates source receipt/finalization bindings, canonical receipt-chain prefixes, signing-key lifecycle and key-cutoff state, predecessor attestation continuity, independent checkpoint usability, and overall recovery-gate convergence. Owner-scoped application methods and HTTP endpoints are wired for attest, audit, snapshot, and reconcile.

## Selected regression tests

The selected regression set contains **59 tests**:

- Batch 102 application, authentication, dependency, import-resolution, and HTTP API-reference checks: 13/13.
- Artifact persistence: 3/3.
- Batch 104 durable execution lease: 7/7.
- Batch 321 lifecycle: 6/6.
- Batch 322 external attestation: 6/6.
- Batch 323 lifecycle: 6/6.
- Batch 324 external attestation: 6/6.
- Batch 325 lifecycle: 6/6.
- Batch 326 external attestation: 6/6.

The selected regression command completed with `1..59`, `# pass 59`, and `# fail 0`. The Batch 322 and Batch 324 static event-allowlist assertions were updated to include Batch 326 in the cumulative schema inventory; those suites then passed. The Batch 326 tests verify empty-history safety, no fabricated source receipts, service/source binding, checkpoint inventory, application convergence and HTTP routes, and strict event schema fields.

## Syntax and configuration

- JavaScript/MJS/CJS syntax checks: **418/418 passed**.
- JSON parsing: **1/1 passed**.
- Relative-import resolution and top-level HTTP application API references passed through Batch 102 regression tests.

## Archive validation

The release archive is tested with `zip -T` and `unzip -t`, then extracted to a separate directory. The packaged and extracted source-file manifests are compared by SHA-256; no missing, extra, or mismatched source files are accepted. The selected regression set and syntax checks are rerun against the extracted tree.

## Not claimed as verified

- Full cumulative `npm test` was not run to a final TAP summary.
- A fully provisioned positive end-to-end flow from verified-current Batch 325 lifecycle receipts through Batch 326 external attestation and checkpoint advancement was not executed.
- Crash injection at every attestation/checkpoint phase boundary was not executed.
- The live HTTP listener was not started with all runtime dependencies installed; route registration and application API references were checked by regression tests.
- `verify:recovery-slo-export` was not run because it requires a `--bundle` input.

## Source-control policy

No GitHub commit was performed.
