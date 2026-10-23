# Batch 291 Validation Report

## Scope

Validated the cumulative Batch 290 source tree with Batch 291 renewal/revocation lifecycle implementation, owner-scoped routes, independent checkpoint inventory, and recovery-gate convergence integration.

## Regression tests

- Batch 102 entrypoint/dependency/API/import checks, artifact tests, and Batch 289–291 focused suites: **29/29 PASS**.
- Batch 104 durable execution lease suite, run separately: **7/7 PASS**.
- Focused suites are required to be rerun from the extracted final ZIP.
- Full cumulative `npm test` was not run to a final TAP summary for this stage; no full-suite PASS is claimed.

## Syntax and configuration

- JavaScript/MJS/CJS syntax checks: **383/383 PASS**.
- `package.json` JSON parse: PASS.
- Batch 102 relative import resolution and HTTP-server application API reference checks: PASS.
- Final extracted ZIP regression runs: focused suites **29/29 PASS**, Batch 104 suite **7/7 PASS**.

## Archive integrity

The cumulative source tree contains **893 files** and the final ZIP contains **912 entries**. `zip -T` and `unzip -t` passed. The ZIP was extracted into a separate directory and compared against the source tree by relative path and SHA-256: **893/893 identical; zero missing, extra, or hash-mismatched files**. All 383 JavaScript/MJS/CJS syntax checks and the focused regression suites were rerun from the extracted tree.

## Limitations

- Positive end-to-end renewal and revocation using a fully current Batch 290 external-attestation chain were not exercised.
- HTTP listener startup was not independently tested because the Express package is not installed in the validation environment; the dependency remains declared in `package.json`.
- These results validate focused tests and packaging, not the complete Agentic AI V4 system.

No GitHub commit was made.
