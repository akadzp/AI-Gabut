# Batch 276 Validation Report

Validation was performed against the cumulative Batch 275 source tree after implementing Batch 276, then repeated against the source extracted from the final ZIP.

## Focused regression tests

- Batch 102 application entrypoint, authentication, import, API, and dependency checks; artifact tests; and Batch 270–276 focused regression tests: **37/37 PASS**.
- Batch 276-specific regression tests: **3/3 PASS**.
- Batch 104 durable execution lease regression rerun separately: **7/7 PASS**, including the lease-heartbeat test that was timing-sensitive during a prior parallel run.
- The same focused suite and Batch 104 rerun passed after extraction from the final ZIP.

## Syntax and configuration

- JavaScript/MJS/CJS syntax: **368/368 PASS**, including after extraction.
- JSON configuration parsing: **1/1 PASS**.
- Relative import resolution and top-level application API route references: PASS through Batch 102 checks.
- Batch 276 HTTP route registration: PASS through focused source-wiring tests.

## Full-suite and runtime limitations

The full cumulative `npm test` suite was not run to completion for Batch 276, so no full-suite PASS is claimed. Positive end-to-end creation of a Batch 276 attestation from a populated, current Batch 275 finalization-receipt chain was not exercised in this run.

HTTP listener startup was not tested because Express is declared but not installed in the validation environment. `verify:recovery-slo-export` was not run because no `--bundle <file.json>` input was supplied.

## Archive validation

- Source/project files: **808**.
- ZIP entries, including directory entries: **827**.
- `zip -T`: PASS.
- `unzip -t`: PASS.
- The ZIP was extracted to a clean directory.
- Source inventory matched exactly: **0 missing, 0 extra files**.
- Per-file SHA-256 comparison: **0 differences**.
- Focused regression tests and syntax checks were rerun against the extracted tree.

GitHub commit: none.
