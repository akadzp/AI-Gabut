# Batch 286 Validation Report

## Focused regression tests

Executed against the cumulative Batch 286 source tree:

- Batch 102 application entrypoint, authentication, dependency, import, and API checks: **13/13 PASS**.
- Artifact tests: **3/3 PASS**.
- Batch 270–286 external-attestation/lifecycle regression suites: **51/51 PASS** (three tests for each of 17 batches).
- Batch 104 durable execution lease suite, run separately to reduce timing interference: **7/7 PASS**.

The combined Batch 102/artifact/Batch 270–286 run passed **67/67 tests**. The separately run Batch 104 suite passed **7/7 tests**. Total selected passing tests across the two runs: **74**.

Batch 286 tests cover empty-history safety, source receipt binding, owner-scoped API and HTTP route wiring, independent checkpoint inventory, recovery-gate convergence, and malformed external-attestation binding rejection.

## Syntax and configuration

- JavaScript/MJS/CJS files checked with `node --check`: **378/378 PASS**.
- `package.json` JSON parsing: **PASS**.
- Relative import resolution and application API references: **PASS** through Batch 102 regression tests.
- Express is declared in `package.json`; HTTP listener startup was not tested in this environment.

## Full cumulative suite

The full cumulative `npm test` suite was **not run to completion for this batch**. This report makes no full-suite PASS claim. The focused regression runs and static syntax checks listed above completed successfully.

## Remaining integration coverage

- A positive end-to-end flow from a fully verified-current Batch 285 lifecycle finalization receipt through Batch 286 external attestation and checkpoint advancement remains untested.
- HTTP listener startup remains untested in an environment with Express installed.

## Archive validation

The complete cumulative source tree was packaged, tested with `zip -T` and `unzip -t`, extracted to a fresh directory, and compared against the packaged file inventory using SHA-256.

- Packaged source/project files: **862**.
- ZIP entries, including directories: **881**.
- Missing files after extraction: **0**.
- Extra files after extraction: **0**.
- SHA-256 mismatches: **0**.
- Focused regression suite rerun against fresh extraction: **67/67 PASS**.
- Batch 104 durable execution lease suite rerun against fresh extraction: **7/7 PASS**.
- JavaScript-family syntax rerun against fresh extraction: **378/378 PASS**.

No GitHub commit was made.
